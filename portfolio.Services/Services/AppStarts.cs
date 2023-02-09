using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace portfolio.Services
{
    public partial class DataServices:IDataServices
    {
        public Task<T> GetRegistrationDropDown<T>()//Here T is what it has Reference to Namespace in the Given DataServices
        {
            return null;
        }
    }
}
