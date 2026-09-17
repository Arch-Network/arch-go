package arch

import (
	"encoding/json"
	"fmt"
)

// Bytes is a byte slice that serializes to JSON as an array of numbers
// (e.g. [1,2,3]) instead of Go's default base64 string. The Arch node
// encodes all variable-length byte fields this way.
type Bytes []byte

// MarshalJSON implements json.Marshaler.
func (b Bytes) MarshalJSON() ([]byte, error) {
	if b == nil {
		return []byte("[]"), nil
	}
	nums := make([]uint16, len(b))
	for i, v := range b {
		nums[i] = uint16(v)
	}
	return json.Marshal(nums)
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *Bytes) UnmarshalJSON(data []byte) error {
	var nums []int
	if err := json.Unmarshal(data, &nums); err != nil {
		return err
	}
	out := make([]byte, len(nums))
	for i, v := range nums {
		if v < 0 || v > 255 {
			return fmt.Errorf("byte array element %d out of range: %d", i, v)
		}
		out[i] = byte(v)
	}
	*b = out
	return nil
}
