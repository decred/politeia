package main

import (
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"time"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
)

const poloURL = "https://poloniex.com/public"
const httpTimeout = time.Second * 3
const pricePeriod = 900

type poloChartData struct {
	Date            uint64  `json:"date"`
	WeightedAverage float64 `json:"weightedAverage"`
}

// GetMonthAverage returns the average USD/DCR price for a given month
func (p *politeiawww) GetMonthAverage(month time.Month, year int) (uint, error) {
	startTime := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
	endTime := startTime.AddDate(0, 1, 0)

	unixStart := startTime.Unix()
	unixEnd := endTime.Unix()

	// Download BTC/DCR and USDT/BTC prices from Poloniex
	dcrPrices, err := getPrices("BTC_DCR", unixStart, unixEnd)
	if err != nil {
		return 0, err
	}
	btcPrices, err := getPrices("USDT_BTC", unixStart, unixEnd)
	if err != nil {
		return 0, err
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
	average = average / float64(len(usdtDcrPrices))

	return uint(math.Round(average * 100)), nil
}

// GetPrices contacts the Poloniex API to download
// price data for a given CC pairing. Returns a map
// of unix timestamp => average price
func getPrices(pairing string, startDate int64, endDate int64) (map[uint64]float64, error) {
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

// GetMonthAverage returns the average USD/DCR price for a given month
func (p *politeiawww) processInvoiceExchangeRate(ier cms.InvoiceExchangeRate) (cms.InvoiceExchangeRateReply, error) {
	reply := cms.InvoiceExchangeRateReply{}

	monthAvg, err := p.GetMonthAverage(time.Month(ier.Month), int(ier.Year))
	if err != nil {
		return reply, err
	}
	reply.ExchangeRate = monthAvg
	return reply, nil
}
