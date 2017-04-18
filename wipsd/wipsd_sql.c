
#include <string.h>
#include "sqlite3.h"
#include "wipsd_sql.h"

int sql_table_row;

int h_sqlite3_get_row(void* data, int n_columns, char** column_values, char** column_names)
{
    sql_table_row++;
	return 0;
}

int sqlite3_get_row( sqlite3 *sql, const char *query, char ***dbResult, int *row, int *col, char **errmsg)
{
    int ret;

    if(sql == NULL)
        return -1;

    sql_table_row = 0;
    ret = sqlite3_exec(sql, query, h_sqlite3_get_row, NULL,NULL);

    *row = sql_table_row;

    return sql_table_row;
}



