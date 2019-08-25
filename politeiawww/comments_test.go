package main

import "testing"

func TestCountersAddPositiveValue(t *testing.T) {
	var cs counters = counters{up: 1, down: 1}
	cs.add(2)
	want := counters{up: 3, down: 1}
	if cs != want {
		t.Errorf("error, got %v, want %v", cs, want)
	}
}

func TestCountersAddNegativeValue(t *testing.T) {
	var cs counters = counters{up: 1, down: 1}
	cs.add(-3)
	want := counters{up: 1, down: 4}
	if cs != want {
		t.Errorf("error, got %v, want %v", cs, want)
	}
}

func TestCountersAddZero(t *testing.T) {
	var cs counters = counters{up: 1, down: 1}
	cs.add(0)
	want := counters{up: 1, down: 1}
	if cs != want {
		t.Errorf("error, got %v, want %v", cs, want)
	}
}

func TestCountersSubtractPositiveValue(t *testing.T) {
	var cs counters = counters{up: 5, down: 6}
	cs.subtract(2)
	want := counters{up: 3, down: 6}
	if cs != want {
		t.Errorf("error, got %v, want %v", cs, want)
	}
}

func TestCountersSubtractNegativeValue(t *testing.T) {
	var cs counters = counters{up: 5, down: 6}
	cs.subtract(-3)
	want := counters{up: 5, down: 3}
	if cs != want {
		t.Errorf("error, got %v, want %v", cs, want)
	}
}

func TestCountersSubtractZero(t *testing.T) {
	var cs counters = counters{up: 1, down: 1}
	cs.subtract(0)
	want := counters{up: 1, down: 1}
	if cs != want {
		t.Errorf("error, got %v, want %v", cs, want)
	}
}
