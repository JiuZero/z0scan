#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/5/10
# JiuZero 2025/7/29
from api import generateResponse, random_num, random_str, VulType, Type, PluginBase, conf, logger, Threads, KB
from helper.basesensitive import sensitive_page_error_message_check
from helper.paramanalyzer import VulnDetector
import re

sqli_errors = {
    "Microsoft SQL": [
        r'System\.Data\.OleDb\.OleDbException', 
        r'\[SQL Server\]', 
        r'\[SQLServer JDBC Driver\]', 
        r'\[Microsoft\]\[ODBC SQL Server Driver\]', 
        r'\[SqlException', 
        r'System\.Data\.SqlClient\.', 
        r'mssql_query\(\)', 
        r'odbc_exec\(\)', 
        r'Microsoft OLE DB Provider for',
        r'Incorrect syntax near', 
        r'Sintaxis incorrecta cerca de', 
        r'Syntax error in string in query expression', 
        r'ADODB\.Field \(0x800A0BCD\)<br>', 
        r"Procedure '[^']+' requires parameter '[^']+'", 
        r"ADODB\.Recordset'", 
        r"ADOConnection", 
        r'\[Macromedia\]\[SQLServer JDBC Driver\]', 
        r'the used select statements have different number of columns', 
        r"Exception.*?\WServer.SqlException", 
        r"Driver.*? SQL[\-\_\ ]*Server", 
        r"OLE DB.*? SQL Server", 
        r"\bSQL Server[^&lt;&quot;]+Driver", 
        r"Warning.*?\W(mssql|sqlsrv)_", 
        r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}", 
        r"System\.Data\.SqlClient\.(SqlException|SqlConnection\.OnError)", 
        r"(?s)Exception.*?\bRoadhouse\.Cms\.", 
        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}", 
        r"ODBC SQL Server Driver", 
        r"ODBC Driver \d+ for SQL Server", 
        r"SQLServer JDBC Driver", 
        r"com\.jnetdirect\.jsql", 
        r"macromedia\.jdbc\.sqlserver", 
        r"Zend_Db_(Adapter|Statement)_Sqlsrv_Exception", 
        r"com\.microsoft\.sqlserver\.jdbc", 
        r"Pdo[./_\\](Mssql|SqlSrv)", 
        r"SQL(Srv|Server)Exception", 
        r"Unclosed quotation mark after the character string", 
    ],
    "DB2": [
        r'DB2 SQL error:', 
        r'internal error \[IBM\]\[CLI Driver\]\[DB2/6000\]', 
        r'SQLSTATE=\d+', 
        r'\[CLI Driver\]', 
        r"CLI Driver.*?DB2", 
        r"\bdb2_\w+\(", 
        r"SQLCODE[=:\d, -]+SQLSTATE", 
        r"com\.ibm\.db2\.jcc", 
        r"Zend_Db_(Adapter|Statement)_Db2_Exception", 
        r"Pdo[./_\\]Ibm", 
        r"DB2Exception", 
        r"ibm_db_dbi\.ProgrammingError", 
    ],
    "SyBase": [
        r"Sybase message:", 
        r'Sybase Driver', 
        r'\[SYBASE\]', 
        r"Warning.*?\Wsybase_", 
        r"SybSQLException", 
        r"Sybase\.Data\.AseClient", 
        r"com\.sybase\.jdbc", 
    ],
    "Microsoft Access": [
        r'Syntax error in query expression', 
        r'Data type mismatch in criteria expression', 
        r'Microsoft JET Database Engine', 
        r"Access Database Engine", 
        r"Microsoft Access (\d+ )?Driver", 
        r"ODBC Microsoft Access", 
        r"Syntax error \(missing operator\) in query expression", 
    ],
    "Oracle": [
        r'(PLS|ORA)-[0-9][0-9][0-9][0-9]',
        r"Oracle error",
        r"Oracle.*?Driver",
        r"Oracle.*?Database", 
        r"Warning.*?\W(oci|ora)_", 
        r"quoted string not properly terminated", 
        r"SQL command not properly ended", 
        r"macromedia\.jdbc\.oracle", 
        r"oracle\.jdbc", 
        r"Zend_Db_(Adapter|Statement)_Oracle_Exception", 
        r"Pdo[./_\\](Oracle|OCI)", 
        r"OracleException", 
    ],
    "PostgreSQL": [
        r'PostgreSQL query failed', 
        r'pg_query\(\) \[:', 
        r'pg_exec\(\) \[:', 
        r'valid PostgreSQL result', 
        r'Npgsql', 
        r"Warning.*?\Wpg_",
        r"org.postgresql.util.PSQLException",
        r"PostgreSQL.*?ERROR", 
        r"PG::SyntaxError:", 
        r"org\.postgresql\.util\.PSQLException", 
        r"ERROR:\s\ssyntax error at or near", 
        r"ERROR: parser: parse error at or near", 
        r"org\.postgresql\.jdbc", 
        r"Pdo[./_\\]Pgsql", 
        r"PSQLException", 
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
        r'DBD::mysql::st execute failed', 
        r"mysqli.query",
        r"SQL syntax.*?MySQL", 
        r"Warning.*?\Wmysqli?_", 
        r"MySQLSyntaxErrorException", 
        r"check the manual that (corresponds to|fits) your ", 
        r"Unknown column '[^ ]+' in 'field list'", 
        r"MySqlClient\.", 
        r"com\.mysql\.jdbc", 
        r"Zend_Db_(Adapter|Statement)_Mysqli_Exception", 
        r"Pdo[./_\\]Mysql", 
        r"MySqlException", 
        r"SQLSTATE\[\d+\]: Syntax error or access violation", 
        r"MemSQL does not support this type of query", 
        r"is not supported by MemSQL", 
        r"unsupported nested scalar subselect", 
    ],
    "Informix": [
        r'com\.informix\.jdbc', 
        r'Dynamic Page Generation Error:', 
        r'An illegal character has been found in the statement', 
        r'\[Informix\]', 
        r"Warning.*?\Wifx_", 
        r"Exception.*?Informix", 
        r"Informix ODBC Driver", 
        r"ODBC Informix driver", 
        r"weblogic\.jdbc\.informix", 
        r"Pdo[./_\\]Informix", 
        r"IfxException", 
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
    "SQLite": [
        r'SQLite/JDBCDriver',
        r'SQLITE_ERROR',
        r'SQLite\.Exception',
        r"Warning.*?sqlite_", 
        r"SQLite\.Exception", 
        r"Warning.*?\W(sqlite_|SQLite3::)", 
        r"\[SQLITE_ERROR\]", 
        r"SQLite error \d+:", 
        r"sqlite3.OperationalError:", 
        r"SQLite3::SQLException", 
        r"org\.sqlite\.JDBC", 
        r"Pdo[./_\\]Sqlite", 
        r"SQLiteException", 
    ], 
    "FrontBase": [
        r"Exception (condition )?\d+\. Transaction rollback", 
        r"com\.frontbase\.jdbc", 
        r"Syntax error 1. Missing", 
        r"(Semantic|Syntax) error [1-4]\d{2}\.", 
    ], 
    "Ingres": [
        r"Warning.*?\Wingres_", 
        r"Ingres SQLSTATE", 
        r"Ingres\W.*?Driver", 
        r"com\.ingres\.gcf\.jdbc", 
    ], 
    "HSQLDB": [
        r"Unexpected end of command in statement \[", 
        r"Unexpected token.*?in statement \[", 
        r"org\.hsqldb\.jdbc", 
    ], 
    "H2": [
        r"org\.h2\.jdbc", 
        r"\[42000-192\]", 
    ], 
    "MonetDB": [
        r"![0-9]{5}![^\n]+(failed|unexpected|error|syntax|expected|violation|exception)", 
        r"\[MonetDB\]\[ODBC Driver", 
        r"nl\.cwi\.monetdb\.jdbc", 
    ], 
    "Apache Derby": [
        r"Syntax error: Encountered", 
        r"org\.apache\.derby", 
        r"ERROR 42X01", 
    ], 
    "Vertica": [
        r", Sqlstate: (3F|42).{3}, (Routine|Hint|Position):", 
        r"/vertica/Parser/scan", 
        r"com\.vertica\.jdbc", 
        r"org\.jkiss\.dbeaver\.ext\.vertica", 
        r"com\.vertica\.dsi\.dataengine", 
    ], 
    "Mckoi": [
        r"com\.mckoi\.JDBCDriver", 
        r"com\.mckoi\.database\.jdbc", 
        r"&lt;REGEX_LITERAL&gt;", 
    ], 
    "Presto": [
        r"com\.facebook\.presto\.jdbc", 
        r"io\.prestosql\.jdbc", 
        r"com\.simba\.presto\.jdbc", 
        r"UNION query has different number of fields: \d+, \d+", 
        r"line \d+:\d+: mismatched input '[^']+'. Expecting:", 
    ], 
    "Altibase": [
        r"Altibase\.jdbc\.driver", 
    ], 
    "MimerSQL": [
        r"com\.mimer\.jdbc", 
        r"Syntax error,[^\n]+assumed to mean", 
    ], 
    "Cache": [
        r"encountered after end of query", 
        r"A comparison operator is required here", 
    ], 
    "CrateDB": [
        r"io\.crate\.client\.jdbc", 
    ], 
    "Raima Database Manager": [
        r"-10048: Syntax error", 
        r"rdmStmtPrepare\(.+?\) returned", 
    ], 
    "Virtuoso": [
        r"SQ074: Line \d+:", 
        r"SR185: Undefined procedure", 
        r"SQ200: No table ", 
        r"Virtuoso S0002 Error", 
        r"\[(Virtuoso Driver|Virtuoso iODBC Driver)\]\[Virtuoso Server\]", 
    ], 
    "SAP MaxDB": [
        r"SQL error.*?POS([0-9]+)", 
        r"Warning.*?\Wmaxdb_", 
        r"DriverSapDB", 
        r"-3014.*?Invalid end of SQL statement", 
        r"com\.sap\.dbtech\.jdbc", 
        r"\[-3008\].*?: Invalid keyword or missing delimiter", 
    ], 
    "FireBird": [
        r"Dynamic SQL Error", 
        r"Warning.*?\Wibase_", 
        r"org\.firebirdsql\.jdbc", 
        r"Pdo[./_\\]Firebird", 
    ], 
    "UNKNOWN": [
        r"Division by zero",
        r"Unable to connect to database",
        r"DB Error",
        r"query failed",
        r"Database.*?error",
        r"SQL command.*?not properly ended",
        r"Malformed query",
        r"Object reference not set to an instance",
        r"DatabaseException",
        r"DBD::mysql::st",
        r"JSQLConnect",
        r"Driver.*?SQL",
        r"Invalid column name",
        r"Column.*?not found",
        r"Table.*?not found",
        r"Server Error in.*?Application",
        r"SQL statement was not properly terminated"
        r"Unclosed quotation mark", 
        r'列 [\"\']?[\w]+[\"\']? 不存在', 
        r'附近的语法不正确|附近有语法错误|后的引号不完整|未闭合'
        r'&lt;b&gt;Warning&lt;/b&gt;\:  ibase_'
        # Java(HQL)
        r'java\.sql\.SQL', 
        r'org\.hibernate\.(query\.)?(Syntax|Query)Exception'
        r'QuerySyntaxException', 
        r'HQLException', 
        r'\[unexpected token: .*?\]', 
        r'could not resolve property: ', 
    ]
}

class Z0SCAN(PluginBase):
    name = "sqli-error"
    desc = 'SQL Error-based Injection'
    version = "2025.7.29"
    risk = 2
        
    def __init__(self):
        super().__init__()
        # 报错注入概率计算相关参数
        self.ERROR_THRESHOLD = 0.6  # 报错注入概率阈值
        self.DBMS_CONFIDENCE = {
            'MySQL': 0.9,
            'PostgreSQL': 0.85,
            'Microsoft SQL': 0.8,
            'Oracle': 0.75,
            'SQLite': 0.7
        }
    
    def calculate_error_probability(self, error_match, dbms_type):
        """
        计算报错注入存在的概率（完全按照DetSQL原有逻辑）
        :param error_match: 正则匹配到的错误信息
        :param dbms_type: 数据库类型
        :return: 报错注入存在的概率(0.0-1.0)
        """
        # 基础概率基于数据库类型
        probability = self.DBMS_CONFIDENCE.get(dbms_type, 0.5)
        
        # 根据错误信息特征调整概率
        error_text = error_match.group()
        
        # 明确的SQL语法错误
        if any(term in error_text.lower() for term in ['syntax', 'sql', 'query']):
            probability = min(probability + 0.2, 1.0)
        
        # 数据库特定错误代码
        elif re.search(r'(ORA-\d+|Msg \d+|Error \d+)', error_text):
            probability = min(probability + 0.15, 1.0) 
        return probability
    
    def audit(self):
        if not self.fingerprints.waf and conf.level != 0:
            _payloads = [
                r"'\")",
                ## 宽字节
                r'鎈\'"\(',
                ## 通用报错
                r';)\\\'\\"',
                r'\' oRdeR bY 500 ',
                r';`)',
                r'\\', 
                r"%%2727", 
                r"%25%27", 
                r"%60", 
                r"%5C",
            ]
            if conf.level == 3: 
                _payloads += [
                    ## 强制报错
                    # MySQL
                    r'\' AND 0xG1#',
                    # PostgreSQL  
                    r"' AND 'a' ~ 'b\[' -- ",
                    # MSSQL
                    r"; RAISERROR('Error generated', 16, 1) -- ", 
                    # Oracle
                    r"' UNION SELECT XMLType('<invalid><xml>') FROM dual -- ",  
                    # SQLite
                    r"' UNION SELECT SUBSTR('o', -1, 1) -- ",
                ]
    
            iterdatas = self.generateItemdatas()
            z0thread = Threads(name="sqli-error")
            z0thread.submit(self.process, iterdatas, _payloads)
    
    def Get_sql_errors(self):
        sql_errors = []
        for database, re_strings in sqli_errors.items():
            for re_string in re_strings:
                sql_errors.append((re.compile(re_string, re.IGNORECASE), database))
        return sql_errors
    
    def process(self, _, _payloads):
        k, v, position = _
        if not VulnDetector(self.requests.url).is_sql_injection(k, v):
            return
        if "email" in str(k) or "@" in str(v):
            _payloads += [
                "'--@example.com", 
                "'+'@example.com", 
            ]
        for _payload in _payloads:
            payload = self.insertPayload({
                "key": k, 
                "value": v, 
                "position": position, 
                "payload": _payload
                })
            if "鎈" in _payload or "%" in _payload:
                quote = False
            else: quote = True
            r = self.req(position, payload, quote=quote)
            if not r:
                continue
            html = r.text
            for sql_regex, dbms_type in self.Get_sql_errors():
                match = sql_regex.search(html)
                if match:
                    # 计算报错注入概率
                    probability = self.calculate_error_probability(match, dbms_type)
                    result = self.generate_result()
                    result.main({
                        "type": Type.REQUEST, 
                        "url": self.requests.url, 
                        "vultype": VulType.SQLI, 
                        "show": {
                            "Position": f"{position} >> {k}",
                            "Payload": payload, 
                            "Msg": f"DBMS_TYPE Maybe {dbms_type} (Probability: {probability:.2f})"
                            }
                        })
                    result.step("Request1", {
                        "request": r.reqinfo, 
                        "response": generateResponse(r), 
                        "desc": f"DBMS_TYPE Maybe {dbms_type} (Probability: {probability:.2f})"
                        })
                    self.success(result)
                    return True
            message_lists = sensitive_page_error_message_check(html)
            # 在SQL报错注入过程中检测到未知报错
            if message_lists:
                probability = 0.5
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": self.requests.url, 
                    "vultype": VulType.SENSITIVE, 
                    "show": {
                        "Position": f"{position} >> {k}",
                        "Payload": payload, 
                        "Msg": f"Receive Error Msg {repr(message_lists)}"
                        }
                    })
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": f"Receive Error Msg {repr(message_lists)}"
                    })
                self.success(result)
                break