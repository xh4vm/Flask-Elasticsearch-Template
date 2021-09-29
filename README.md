# Flask-Elasticsearch-Template

Заготовка для более быстрого развертывания стека Flask-PostgreSQL-Elasticsearch

## Для билда в интерактивном режиме выполнить следующие действия:
```
make build  
```

## Для билда в режиме демона выполнить следующие действия:
```
make build-daemon
```

## Если нет необходимости ребилдить, то можно простро запустить одной из команд:
```
make run
make run-daemon
```

Теперь в браузере по ссылке http://localhost:8000 будет транслироваться наш проект

## Для запуска тестов:
```
make test
```

## Для обновления структуры базы данных:
```
make migrate
```
