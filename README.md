# pwd-password

Ruby gem: парольный генератор + оценщик сложности + CLI.

## CLI

### Generate


ruby pwd generate --length 16 --symbols --numbers
```

Опционально сохранять в зашифрованный файл:


ruby pwd generate --length 16 --symbols --store passwords.enc --secret "my-passphrase"
```

Доступны шифры:
- `aes_gcm` (по умолчанию)
- `xor` (упрощенный вариант)

### Check


ruby pwd check "my_password"
```

### Decrypt (просмотр содержимого хранилища)


ruby pwd decrypt --file passwords.enc --secret "my-passphrase"
```

В PowerShell `pwd` - alias на `Get-Location`, поэтому если команда не запускается, попробуй `pwd.exe ...` после установки гем.

## API

```ruby
require "pwd_password"

Password.generate(length: 16, numbers: true, symbols: true, uppercase: true)
Password.strength("MyPassword123!")
```

