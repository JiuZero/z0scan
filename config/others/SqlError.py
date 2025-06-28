#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/5/15

rules = {
    "Microsoft SQL": [
        r'System\.Data\.OleDb\.OleDbException', 
        r'\[SQL Server\]', 
        r'\[SQLServer JDBC Driver\]', 
        r'\[Microsoft\]\[ODBC SQL Server Driver\]', 
        r'\[SqlException', 
        r'System\.Data\.SqlClient\.SqlException', 
        r'mssql_query\(\)', 
        r'odbc_exec\(\)', 
        r'Microsoft OLE DB Provider for',
        r'Incorrect syntax near', 
        r'Sintaxis incorrecta cerca de', 
        r'Syntax error in string in query expression', 
        r'ADODB\.Field \(0x800A0BCD\)<br>', 
        r"Procedure '[^']+' requires parameter '[^']+'", 
        r"ADODB\.Recordset'", 
        r"Unclosed quotation mark ", 
        r'\[Macromedia\]\[SQLServer JDBC Driver\]', 
        r'the used select statements have different number of columns',
    ],
    "DB2": [
        r'DB2 SQL error:', 
        r'internal error \[IBM\]\[CLI Driver\]\[DB2/6000\]', 
        r'SQLSTATE=\d+', 
        r'\[CLI Driver\]', 
    ],
    "SyBase": [
        r"Sybase message:", 
    ],
    "Microsoft Access": [
        r'Syntax error in query expression', 
        r'Data type mismatch in criteria expression', 
        r'Microsoft JET Database Engine', 
        r'\[Microsoft\]\[ODBC Microsoft Access Driver\]', 
    ],
    "Oracle": [
        r'(PLS|ORA)-[0-9][0-9][0-9][0-9]',
    ],
    "PostgreSQL": [
        r'PostgreSQL query failed:', 
        r'supplied argument is not a valid PostgreSQL result', 
        r'pg_query\(\) \[:', 
        r'pg_exec\(\) \[:', 
        r'valid PostgreSQL result', 
        r'Npgsql', 
    ],
    "MySQL": [
        r'valid MySQL',
        r'mysql_', 
        r'on MySQL result index', 
        r'You have an error in your SQL syntax', 
        r'MySQL server version for the right syntax to use', 
        r'\[MySQL\]\[ODBC', 
        r"Column count doesn't match", 
        r"the used select statements have different number of columns", 
        r"Table '[^']+' doesn't exist", 
    ],
    "Informix": [
        r'com\.informix\.jdbc', 
        r'Dynamic Page Generation Error:', 
        r'An illegal character has been found in the statement', 
    ],
    "InterBase": [
        r'<b>Warning</b>:  ibase_', 
        r'Dynamic SQL Error', 
        r'Unexpected end of command in statement',
    ],
    "DML": [
        r'\[DM_QUERY_E_SYNTAX\]', 
        r'has occurred in the vicinity of:', 
        r'A Parser Error \(syntax error\)', 
    ],
    "Java(HQL)": [
        r'java\.sql\.SQLException', 
        r'java\.sql\.SQLSyntaxErrorException',
        r'org\.hibernate\.(query\.)?(Syntax|Query)Exception'
        r'QuerySyntaxException', 
        r'HQLException', 
        r'\[unexpected token: .*?\]', 
        r'could not resolve property: ', 
    ],
    "SQLite": [
        r'SQLite/JDBCDriver',
        r'System\.Data\.SQLite\.SQLiteException',
        r'SQLITE_ERROR',
        r'SQLite\.Exception',
    ],
}