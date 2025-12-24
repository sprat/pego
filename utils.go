package pego

import "reflect"

func getStructSize[T any]() int64 {
	return int64(reflect.TypeFor[T]().Size())
}
