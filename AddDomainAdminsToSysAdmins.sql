EXEC master..sp_addsrvrolemember @loginame = N'contoso\domain admins', @rolename = N'sysadmin'
EXEC master..sp_addsrvrolemember @loginame = N'contoso\SCCM-01$', @rolename = N'sysadmin'
EXEC master..sp_addsrvrolemember @loginame = N'contoso\domain computers', @rolename = N'sysadmin'
EXEC master..sp_addsrvrolemember @loginame = N'NT SERVICE\MSSQLSERVER', @rolename = N'sysadmin'
EXEC master..sp_addsrvrolemember @loginame = N'NT AUTHORITY\SYSTEM', @rolename = N'sysadmin'