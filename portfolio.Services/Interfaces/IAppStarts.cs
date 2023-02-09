using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace portfolio.Services
{
    public partial interface IDataServices
    {
        Task<T> GetRegistrationDropDown<T>();
    }
}
