declare module 'sql.js' {
  interface SqlJsStatic {
    Database: typeof Database;
  }

  interface QueryExecResult {
    columns: string[];
    values: unknown[][];
  }

  interface Statement {
    bind(params?: unknown[]): boolean;
    step(): boolean;
    getAsObject(): Record<string, unknown>;
    free(): boolean;
    reset(): void;
  }

  class Database {
    constructor(data?: ArrayLike<number> | Buffer | null);
    run(sql: string, params?: unknown[]): Database;
    exec(sql: string): QueryExecResult[];
    prepare(sql: string): Statement;
    export(): Uint8Array;
    close(): void;
  }

  export { Database, SqlJsStatic, QueryExecResult, Statement };
  export default function initSqlJs(config?: Record<string, unknown>): Promise<SqlJsStatic>;
}
