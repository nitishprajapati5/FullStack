using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace portfolio.Models.Tables
{
    public class GroupDetails
    {
        public long Id { get; set; }
        public long GroupId { get; set; }
        public string? GroupName { get; set;}
        public string? Description { get; set; }
        public bool IsDeleted { get; set; }
        public long Sequence { get; set; }
        public long Value { get; set; }
    }
}
