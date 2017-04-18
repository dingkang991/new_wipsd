#ifndef __WIPSD_SQL_H__
#define __WIPSD_SQL_H__

int h_sqlite3_get_row(void* data, int n_columns, char** column_values, char** column_names);
int sqlite3_get_row( sqlite3 *sql, const char *query, char ***dbResult, int *row, int *col, char **errmsg);

#endif
