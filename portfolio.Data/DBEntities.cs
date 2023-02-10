﻿using Microsoft.EntityFrameworkCore;
using portfolio.Models.Tables;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace portfolio.Data
{
    public class DBEntities:DbContext
    {
        public DBEntities()
        {

        }

        public DBEntities(DbContextOptions<DBEntities> options) : base(options)
        {

        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
        }

        public DbSet<GroupDetails> GroupDetail { get; set; }

    }
}
