package util

func SearchElement(arr []string, word string) bool {
	for _, val := range arr {
		if val == word {
			return true
		}
	}
	return false
}

func SearchDelete(arr []string, word string) ([]string, bool) {
	var list []string
	var ischange bool
	for index, val := range arr {
		if val == word {
			list = append(arr[:index], arr[index+1:]...)
			ischange = true
		}
	}
	return list, ischange
}
