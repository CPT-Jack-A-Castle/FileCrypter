# FileCrypter
## Функционал
* Шифровка файла
* Расшифровка файла

## В чем суть
Проще объяснить на примере: 
* Пользователь указывает файл, который хочет зашифровать
* Вводит пароль
* Программа вычисляет хеш-сумму пароля и использует в качестве ключа для AES шифрования
* Исходный файл заменяется зашифрованным

Аналогично с дешифрованием

## Почему это безопасно
FileCrypter использует AES шифрование, которое обладает [высокой криптостойкостью](https://ru.wikipedia.org/wiki/AES_(%D1%81%D1%82%D0%B0%D0%BD%D0%B4%D0%B0%D1%80%D1%82_%D1%88%D0%B8%D1%84%D1%80%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D1%8F)#%D0%9A%D1%80%D0%B8%D0%BF%D1%82%D0%BE%D1%81%D1%82%D0%BE%D0%B9%D0%BA%D0%BE%D1%81%D1%82%D1%8C)

## Установка
```pip install -r requirements.txt```
## Как использовать
На данный момент в программе можно использовать два параметра:
* шифрование: ```-e / --encrypt имя_файла```
* дешифрование: ```-d / --decrypt имя_файла```

Запуск программы без параметров ничего не изменит

## Пример
```python main.py -e input.txt``` то же самое, что и ```python main.py --encrypt input.txt``` 

```python main.py -d input.txt``` то же самое, что и ```python main.py --decrypt input.txt``` 
