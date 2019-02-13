using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

public class CallSQLContext : DbContext
{
    public CallSQLContext() : base("name=CallMSSSQLContext") { }

    public DbSet<Call> Calls { get; set; }
}
