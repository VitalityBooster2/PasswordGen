# pwd-password

Ruby gem: парольный генератор + оценщик сложности + CLI.

## CLI

### Generate

```sh
pwd generate --length 16 --symbols --numbers
```

Опционально сохранять в зашифрованный файл:

```sh
pwd generate --length 16 --symbols --store passwords.enc --secret "my-passphrase"
```

Доступны шифры:
- `aes_gcm` (по умолчанию)
- `xor` (упрощенный вариант)

### Check

```sh
pwd check "my_password"
```

В PowerShell `pwd` - alias на `Get-Location`, поэтому если команда не запускается, попробуй `pwd.exe ...` после установки гем.

## API

```ruby
require "pwd_password"

Password.generate(length: 16, numbers: true, symbols: true, uppercase: true)
Password.strength("MyPassword123!")
```

