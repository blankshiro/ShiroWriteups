# Cheatsheet

>   Source: [PortSwigger](https://portswigger.net/web-security/sql-injection/cheat-sheet)

## String concatenation

You can concatenate together multiple strings to make a single string.

| Oracle     | `'foo'||'bar'`                                               |
| :--------- | ------------------------------------------------------------ |
| Microsoft  | `'foo'+'bar'`                                                |
| PostgreSQL | `'foo'||'bar'`                                               |
| MySQL      | `'foo' 'bar'` [Note the space between the two strings] `CONCAT('foo','bar')` |

## Comments

You can use comments to truncate a query and remove the portion of the original query that follows your input.

| Oracle     | `--comment`                                                  |
| :--------- | ------------------------------------------------------------ |
| Microsoft  | `--comment/*comment*/`                                       |
| PostgreSQL | `--comment/*comment*/`                                       |
| MySQL      | `#comment` `-- comment` [Note the space after the double dash] `/*comment*/` |

## Database contents

You can list the tables that exist in the database, and the columns that those tables contain.

| Oracle     | `SELECT * FROM all_tablesSELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'` |
| :--------- | ------------------------------------------------------------ |
| Microsoft  | `SELECT * FROM information_schema.tablesSELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| PostgreSQL | `SELECT * FROM information_schema.tablesSELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| MySQL      | `SELECT * FROM information_schema.tablesSELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
