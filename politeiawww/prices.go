// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	cms "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	www "github.com/thi4go/politeia/politeiawww/api/www/v1"
	database "github.com/thi4go/politeia/politeiawww/cmsdatabase"
)

const binanceURL = "https://api.binance.com"
const poloURL = "https://poloniex.com/public"
const httpTimeout = time.Second * 3
const pricePeriod = 900

const dcrSymbolBinance = "DCRBTC"
const usdtSymbolBinance = "BTCUSDT"

const dcrSymbolPolo = "BTC_DCR"
const usdtSymbolPolo = "USDT_BTC"

type poloChartData struct {
	Date            uint64  `json:"date"`
	WeightedAverage float64 `json:"weightedAverage"`
}

// Set the last date to use polo as 4/1/2019.  If any start date requested is
// after that date then use Binance instead.
var endPoloDate = time.Date(2019, 4, 1, 0, 0, 0, 0, time.UTC)

// getMonthAverage returns the average USD/DCR price for a given month
func (p *politeiawww) getMonthAverage(month time.Month, year int) (uint, error) {
	startTime := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
	endTime := startTime.AddDate(0, 1, 0)

	if time.Now().Before(endTime) {
		return 0, fmt.Errorf(
			"Requested rate end time (%v) is past current time (%v)",
			endTime,
			time.Now())
	}

	unixStart := startTime.Unix()
	unixEnd := endTime.Unix()

	var dcrPrices map[uint64]float64
	var btcPrices map[uint64]float64
	var err error

	// Use Binance if start date is AFTER 3/31/19
	if startTime.Before(endPoloDate) {
		// Download BTC/DCR and USDT/BTC prices from Polo
		dcrPrices, err = getPricesPolo(dcrSymbolPolo, unixStart, unixEnd)
		if err != nil {
			return 0, fmt.Errorf("getPricesPolo %v: %v", dcrSymbolPolo, err)
		}
		btcPrices, err = getPricesPolo(usdtSymbolPolo, unixStart, unixEnd)
		if err != nil {
			return 0, fmt.Errorf("getPricesPolo %v: %v", usdtSymbolPolo, err)
		}
	} else {
		// Download BTC/DCR and USDT/BTC prices from Binance
		dcrPrices, err = getPricesBinance(dcrSymbolBinance, unixStart, unixEnd)
		if err != nil {
			return 0, fmt.Errorf("getPricesBinance %v: %v", dcrSymbolBinance, err)
		}
		btcPrices, err = getPricesBinance(usdtSymbolBinance, unixStart, unixEnd)
		if err != nil {
			return 0, fmt.Errorf("getPricesBinance %v: %v", usdtSymbolBinance, err)
		}
	}
	// Create a map of unix timestamps => average price
	usdtDcrPrices := make(map[uint64]float64)

	// Select only timestamps which appear in both charts to
	// populate the result set. Multiply BTC/DCR rate by
	// USDT/BTC rate to get USDT/DCR rate.
	for timestamp, dcr := range dcrPrices {
		if btc, ok := btcPrices[timestamp]; ok {
			usdtDcrPrices[timestamp] = dcr * btc
		}
	}

	// Calculate and return the average of all USDT/DCR prices
	var average float64
	for _, price := range usdtDcrPrices {
		average += price
	}
	average /= float64(len(usdtDcrPrices))

	return uint(math.Round(average * 100)), nil
}

// getPricesPolo contacts the Poloniex API to download
// price data for a given CC pairing. Returns a map
// of unix timestamp => average price
// Currently being replaced by Binance data due to Polo's ongoing issues with
// volume.
func getPricesPolo(pairing string, startDate int64, endDate int64) (map[uint64]float64, error) {
	// Construct HTTP request and set parameters
	req, err := http.NewRequest(http.MethodGet, poloURL, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Set("command", "returnChartData")
	q.Set("currencyPair", pairing)
	q.Set("start", strconv.FormatInt(startDate, 10))
	q.Set("end", strconv.FormatInt(endDate, 10))
	q.Set("period", strconv.Itoa(pricePeriod))
	req.URL.RawQuery = q.Encode()

	// Create HTTP client,
	httpClient := http.Client{
		Timeout: httpTimeout,
	}

	// Send HTTP request
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	// Read response and deserialise JSON
	decoder := json.NewDecoder(resp.Body)
	var chartData []poloChartData
	err = decoder.Decode(&chartData)
	if err != nil {
		return nil, err
	}

	// Create a map of unix timestamps => average price
	prices := make(map[uint64]float64, len(chartData))
	for _, data := range chartData {
		prices[data.Date] = data.WeightedAverage
	}

	return prices, nil
}

// getPricesBinance contacts the Binance API to download
// price data for a given CC pairing. Returns a map
// of unix timestamp => average price
func getPricesBinance(pairing string, startDate int64, endDate int64) (map[uint64]float64, error) {
	// Construct HTTP request and set parameters
	req, err := http.NewRequest(http.MethodGet, binanceURL+"/api/v1/klines", nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Set("symbol", pairing)
	q.Set("startTime", strconv.FormatInt(startDate*1000, 10))
	q.Set("endTime", strconv.FormatInt(endDate*1000, 10))

	// Request 1 hour intervals since there is a 1000 point limit on requests
	// 31 Days * 24 Hours = 720 data points
	q.Set("interval", "1h")
	q.Set("limit", "1000")

	req.URL.RawQuery = q.Encode()

	// Create HTTP client,
	httpClient := http.Client{
		Timeout: httpTimeout,
	}

	// Send HTTP request
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var chartData [][]json.RawMessage

	// Read response and deserialise JSON into [][]json.RawMessage
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&chartData)
	if err != nil {
		return nil, err
	}

	prices := make(map[uint64]float64, len(chartData))
	for _, v := range chartData {
		var openTime uint64 // v[0]
		var highStr string  // v[2]
		var lowStr string   // v[3]

		err := json.Unmarshal(v[0], &openTime)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(v[2], &highStr)
		if err != nil {
			return nil, err
		}
		high, err := strconv.ParseFloat(highStr, 64)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(v[3], &lowStr)
		if err != nil {
			return nil, err
		}
		low, err := strconv.ParseFloat(lowStr, 64)
		if err != nil {
			return nil, err
		}
		// Create a map of unix timestamps => average price
		prices[openTime/1000] = (high + low) / 2
	}
	return prices, nil
}

// processInvoiceExchangeRate handles requests to return an exchange for a given
// month and year. It first attempts to find the exchange rate from the database
// and if none is found it requests the monthly average from the exchange API.
func (p *politeiawww) processInvoiceExchangeRate(ier cms.InvoiceExchangeRate) (cms.InvoiceExchangeRateReply, error) {
	reply := cms.InvoiceExchangeRateReply{}

	monthAvg, err := p.cmsDB.ExchangeRate(int(ier.Month), int(ier.Year))
	if err != nil {
		if err == database.ErrExchangeRateNotFound {
			monthAvgRaw, err := p.getMonthAverage(time.Month(ier.Month), int(ier.Year))
			if err != nil {
				log.Errorf("processInvoiceExchangeRate: getMonthAverage: %v", err)
				return reply, www.UserError{
					ErrorCode: cms.ErrorStatusInvalidExchangeRate,
				}
			}

			monthAvg = &database.ExchangeRate{
				Month:        ier.Month,
				Year:         ier.Year,
				ExchangeRate: monthAvgRaw,
			}
			err = p.cmsDB.NewExchangeRate(monthAvg)
			if err != nil {
				return reply, err
			}
		} else {
			return reply, err
		}
	}
	reply.ExchangeRate = monthAvg.ExchangeRate
	return reply, nil
}
