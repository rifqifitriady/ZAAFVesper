//go:build race

package ps

// raceEnabled scales down the heavy memory tests under -race, where the
// detector makes JSON decoding of megabyte lines ~20x slower.
const raceEnabled = true
