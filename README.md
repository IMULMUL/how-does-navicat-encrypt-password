# How Does Navicat Encrypt Password?

This repo will tell you how Navicat encrypts password and offer a tool to reveal passwords encrypted by Navicat.

## 1. What is Navicat?

Navicat is a series of graphical database management and development software produced by PremiumSoft CyberTech Ltd. for MySQL, MariaDB, Oracle, SQLite, PostgreSQL and Microsoft SQL Server.

It has an Explorer-like graphical user interface and supports multiple database connections for local and remote databases. Its design is made to meet the needs of a variety of audiences, from database administrators and programmers to various businesses/companies that serve clients and share information with partners.

## 2. What does indicate that Navicat encrypts password?

If you use Navicat to manage one of your databases, the first thing you should do is to create a connection to the database. So that means you should fill textboxes on the window showed below with the database's information like `Host name`, `User name`, `Password` and so on.

<div align="center">
  <img src = "doc/NavicatSetUpConnection.gif">
</div>

If you check "Save Password", after you click "Ok" button, Navicat will encrypt the password and then save the connection configuration, containing encrypted password, in **Windows Registry**. The exact path is showed below:

|Database Type|Path                                                                                       |
|-------------|-------------------------------------------------------------------------------------------|
|MySQL        |HKEY_CURRENT_USER\\Software\\PremiumSoft\\Navicat\\Servers\\`<your connection name>`       |
|MariaDB      |HKEY_CURRENT_USER\\Software\\PremiumSoft\\NavicatMARIADB\\Servers\\`<your connection name>`|
|MongoDB      |HKEY_CURRENT_USER\\Software\\PremiumSoft\\NavicatMONGODB\\Servers\\`<your connection name>`|
|Microsoft SQL|HKEY_CURRENT_USER\\Software\\PremiumSoft\\NavicatMSSQL\\Servers\\`<your connection name>`  |
|Oracle       |HKEY_CURRENT_USER\\Software\\PremiumSoft\\NavicatOra\\Servers\\`<your connection name>`    |
|PostgreSQL   |HKEY_CURRENT_USER\\Software\\PremiumSoft\\NavicatPG\\Servers\\`<your connection name>`     |
|SQLite       |HKEY_CURRENT_USER\\Software\\PremiumSoft\\NavicatSQLite\\Servers\\`<your connection name>` |

The following is an example:

<div align="center">
  <img src = "doc/NavicatInRegistry.PNG">
</div>

## 3. How does Navicat encrypt password?

See [here](doc/how-does-navicat-encrypt-password.md).

## 4. How to use the sample code in python3 folder?

* Please make sure you have `Python3`.

* Please make sure you have following packages if you want to use `navicat-cipher.py` and `ncx-dump.py`:

  ```
  cryptography
  pywin32       // required if you want to get navicat_cred from Windows Credential Manager automatically
  ```

  You can install them via command:

  ```console
  $ pip install cryptography pywin32
  ```

* Please make sure that you have package `pywin32` if you want to use `show-navicat.py`.

  You can install package `pywin32` via command:

  ```console
  $ pip install pywin32
  ```

1. __navicat-cipher.py__

   ```
   usage: navicat-cipher.py enc [-h] (-v1 | -v2 | -v3) [--cred CRED] PASSWD

   positional arguments:
     PASSWD       the password in plaintext

   options:
     -h, --help   show this help message and exit
     -v1          use v1 algorithm
     -v2          use v2 algorithm
     -v3          use v3 algorithm
     --cred CRED  the value of navicat_cred, which is used by -v3
   ```

   ```
   usage: navicat-cipher.py dec [-h] (-v1 | -v2 | -v3) [--cred CRED] PASSWD

   positional arguments:
     PASSWD       the password in ciphertext

   options:
     -h, --help   show this help message and exit
     -v1          use v1 algorithm
     -v2          use v2 algorithm
     -v3          use v3 algorithm
     --cred CRED  the value of navicat_cred, which is used by -v3
   ```

   __Example:__

   ```console
   $ ./navicat-cipher.py enc -v1 "This is a test"
   0EA71F51DD37BFB60CCBA219BE3A

   $ ./navicat-cipher.py dec -v1 0EA71F51DD37BFB60CCBA219BE3A
   This is a test

   $ ./navicat-cipher.py enc -v2 "This is a test"
   B75D320B6211468D63EB3B67C9E85933

   $ ./navicat-cipher.py dec -v2 B75D320B6211468D63EB3B67C9E85933
   This is a test

   //
   // the following command requires `pywin32` package
   //   to get `navicat_cred` of current Windows system
   //
   $ ./navicat-cipher.py dec -v3 67A1E0646999D37518B3699837061DB762E536035CFE0BC7D7531B6099C5DB1803F539BF3D9FA7AD8D0D1035
   dummy123456

   //
   // the following command requires `pywin32` package
   //   to get `navicat_cred` of current Windows system
   //
   $ ./navicat-cipher.py enc -v3 dummy123456
   31BE04EE58C3C3A5B3777F1BA137AF2963AF15BAF2AE730FFE13E21DDBEF12F8D4ED80D7DEB51551351083C1

   //
   // `pywin32` package is not required
   //   because `navicat_cred` is given via `--cred` argument
   //
   $ ./navicat-cipher.py enc -v3 --cred f2bf93f14d487e3c2404eef3877b5a4c6d1e2d03342aa51283a6786297b26510 dummy123456
   930868109524B44DBB875A8712647C50986810B391314EFD20ABE412629B8CCA49A0A59711BBA793479D433A

   //
   // `pywin32` package is not required
   //   because `navicat_cred` is given via `--cred` argument
   //
   $ ./navicat-cipher.py dec -v3 --cred f2bf93f14d487e3c2404eef3877b5a4c6d1e2d03342aa51283a6786297b26510 930868109524B44DBB875A8712647C50986810B391314EFD20ABE412629B8CCA49A0A59711BBA793479D433A
   dummy123456
   ```

2. __ncx-dump.py__

   Show database servers' information inside `*.ncx` file.

   ```
   usage: ncx-dump.py [-h] FILE

   positional arguments:
     FILE        path to .ncx file

   options:
     -h, --help  show this help message and exit
   ```

   __Example:__

   ```console
   $ ./ncx-dump.py /c/Users/lenovo/Desktop/connections.ncx
   [MYSQL:dummy]
   host = localhost
   port = 3306
   username = root
   password = dummy123456

   [POSTGRESQL:postgresql-example]
   host = localhost
   port = 5432
   username = postgres
   password = passwd@postgresql
   ssh-host = postgresql-example.com
   ssh-port = 22
   ssh-username = root
   ssh-password = passwd@postgresql.ssh

   [SQLSERVER:mssql-example]
   host = mssql-example
   port = 1433
   username = sa
   password = sa-password

   [ORACLE:oracle-example]
   host = oracle-example
   port = 1521
   database = ORCL
   username = admin
   password = admin123456

   [SQLITE:dummysql]
   file = C:\Users\Hypersine\Desktop\dummysql.db
   username =
   password =
   ```

3. __show-navicat.py__

   Just run it on Windows.
   
   It will list all Navicat configurations stored in Windows Registry.

   __Example:__

   ```console
   $ ./show-navicat.py
   [MySQL:dummy]
   host = localhost
   port = 3306
   username = root
   password = dummy123456

   [MSSQL:mssql-example]
   host = mssql-example
   port = 1433
   username = sa
   password = sa-password

   [OracleSQL:oracle-example]
   host = oracle-example
   port = 1521
   database = ORCL
   username = admin
   password = admin123456

   [PostgreSQL:postgresql-example]
   host = localhost
   port = 5432
   username = postgres
   password = passwd@postgresql
   ssh-host = postgresql-example.com
   ssh-port = 22
   ssh-username = root
   ssh-password = passwd@postgresql.ssh

   [SQLite:dummysql]
   file = C:\Users\Hypersine\Desktop\dummysql.db
   username =
   password 
   ```
