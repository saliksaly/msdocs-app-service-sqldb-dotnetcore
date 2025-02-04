using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using DotNetCoreSqlDb.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;

namespace DotNetCoreSqlDb.Data
{
    public class MyDatabaseContext : IdentityDbContext<IdentityUser>
    {
        public MyDatabaseContext (DbContextOptions<MyDatabaseContext> options)
            : base(options)
        {
        }

        public DbSet<DotNetCoreSqlDb.Models.Todo> Todo { get; set; } = default!;
    }
}
