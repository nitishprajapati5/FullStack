using Microsoft.Extensions.Configuration;
using portfolio.Data;
using portfolio.Data.UnitofWork;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace portfolio.Services
{
    public partial class DataServices:IDataServices
    {
        private readonly UnitOfWork _unitOfWork;

        public DataServices(IConfiguration configuration,UnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        public async Task<List<T>> GetAllBySPName<T>(string spName)
        {
            try
            {
                return await _unitOfWork.ExecuteSP<T>(spName,null);
            }
            catch(Exception)
            {
                throw;
            }
        }

        //public async Task<int> ExecuteNonQueryBySPName(string spName)
        //{
        //    try
        //    {
        //        return await _unitOfWork.ExecuteNonQueryAsync(spName, null);
        //    }
        //    catch (Exception)
        //    {
        //        throw;
        //    }
        //}

        public async Task Create<T>(T obj) where T : class
        {
            try
            {
                await _unitOfWork.Repository<T>().Create(obj);
                await _unitOfWork.Save();
            }
            catch (Exception)
            {
                throw;
            }
        }

        public async Task Update<T>(T obj) where T : class
        {
            try
            {
                await _unitOfWork.Repository<T>().Update(obj);
                await _unitOfWork.Save();
            }
            catch (Exception)
            {
                throw;
            }
        }

        public GenericRepository<T> ServiceRepository<T>() where T : class
        {
            try
            {
                return _unitOfWork.Repository<T>();
            }
            catch (Exception)
            {
                throw;
            }
        }


    }
}
