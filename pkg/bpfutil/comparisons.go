package bpfutil

// EqualIntSliceUnordered checks if two integer slices contain the same elements, order agnostic.
func EqualIntSliceUnordered(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) == 0 {
		return true
	}

	counts := make(map[int]int, len(a))
	for _, x := range a {
		counts[x]++
	}
	for _, x := range b {
		if counts[x] == 0 {
			return false
		}
		counts[x]--
	}
	return true
}
