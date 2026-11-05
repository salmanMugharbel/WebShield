"""
!!! INTENTIONALLY VULNERABLE CODE - EDUCATIONAL USE ONLY !!!

Everything in this package is deliberately insecure so that students can see
how SQL Injection works. It is isolated from the main application:

* it uses a throw-away IN-MEMORY SQLite database with fictional accounts,
* it never opens the main webshield.db file,
* a SQLite authorizer only allows read-only SELECT statements,
* a progress handler aborts runaway queries.
"""
