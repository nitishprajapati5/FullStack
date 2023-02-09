using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace portfolio.Models.Response
{
    public class MiscellenousResponse
    {
        public class RegistrationDropDown
        {
            public long Id { get; set; }
            public string? GroupName { get; set; }
            public string? Description { get; set; }
            public long? Sequence { get; set; }
            public long? Value { get; set; }
        }
    }
}
