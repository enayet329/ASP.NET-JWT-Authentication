using DotNet8JwtAuthentication.Models;
using Microsoft.EntityFrameworkCore;

namespace DotNet8JwtAuthentication.Data
{
    public class JwtDb : DbContext
    {
        public JwtDb(DbContextOptions options) : base(options)
        {

        }

        public DbSet<User> Users { get; set; }
    }
}
