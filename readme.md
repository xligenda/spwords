# Пакет для взаимодействия с API серверов СП на Go

[Документация API](https://github.com/sp-worlds/api-docs)

## Быстрое начало

### Устрановка

```sh
go get github.com/xligenda/spworlds
```

### Использование

Для начала вам нужно указать ID и Token вашей карты, найти их можно [здесь](https://github.com/sp-worlds/api-docs/blob/main/AUTHORIZATION.md#%D0%BF%D0%BE%D0%BB%D1%83%D1%87%D0%B5%D0%BD%D0%B8%D0%B5-%D1%82%D0%BE%D0%BA%D0%B5%D0%BD%D0%B0-%D0%B8-id-%D0%BA%D0%B0%D1%80%D1%82%D1%8B)

```go
package main

import (
	"fmt"

	"github.com/xligenda/spworlds"
)

func main() {
	api := spworlds.NewClient("card id", "card token")

	resp, err := api.Me()
	if err != nil || resp == nil {
		panic(err)
	}

	fmt.Printf("Никнейм владельца карточки: %s", *resp.Username)
}
```

Перевод АРов на другую карту
```go
package main

import (
	"fmt"

	"github.com/xligenda/spworlds"
)

func main() {
	api := spworlds.NewClient("card id", "card token")

	// Перевод 10 АР на карту с номером OSTER с комментарием "Подарок"
	resp, err := api.CreateTransaction(spworlds.CreateTransactionOptions{
		Receiver: "OSTER",
		Amount:   10,
		Comment:  "Подарок",
	})
	if err != nil || resp == nil {
		panic(err)
	}

	fmt.Printf("Оставшийся баланс карты: %d", resp.Balance)
}
```
