using Microsoft.Extensions.Options;
using portfolio.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static portfolio.Models.DataRequest;

namespace portfolio.Services
{
    public class StaticService
    {
        private readonly AppConfig _appConfig;
        private readonly IDataServices _dataService;

        public StaticService(IOptions<AppConfig> appConfig,IDataServices dataServices)
        {
            _appConfig = appConfig.Value;
            _dataService = dataServices;
        }

        public AppConfig GetAppConfig()
        {
            return _appConfig;
        }

        public portfolio.Data.GenericRepository<T> ServiceRepository<T>()where T:class
        {
            try
            {
                return _dataService.ServiceRepository<T>();
            }
            catch(Exception)
            {
                throw;
            }
        }

        #region Private Methods

        private string GetProcedureName<T>(T obj)
        {
            try
            {
                System.Reflection.PropertyInfo propertyInfo = obj.GetType().GetProperty(nameof(SPBase.Procedure));
                return propertyInfo.GetValue(obj, null).ToString();
            }
            catch (Exception)
            {
                throw;
            }
        }

        #endregion
    }
}
