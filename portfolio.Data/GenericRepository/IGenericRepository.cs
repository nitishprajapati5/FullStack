using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;

namespace portfolio.Data.GenericRepository
{
    public  interface IGenericRepository<T>
        where T : class
    {
        #region Interface Method Declaration
        IQueryable<T> GetAll(Expression<Func<T, object>>[]? includes = null);

        IQueryable<T> GetWhere(Expression<Func<T, bool>> where, Expression<Func<T, object>>[]? includes = null);

        Task<T> GetSingle(Expression<Func<T, bool>> where, Expression<Func<T, object>>[]? includes = null);

        Task<T> GetById(long id, Expression<Func<T, object>>[]? includes = null);

        Task Create(T entity);

        Task Update(T entity);

        Task UpdateList(List<T> entity);

        Task Save();

        void Dispose();
        #endregion

    }
}
