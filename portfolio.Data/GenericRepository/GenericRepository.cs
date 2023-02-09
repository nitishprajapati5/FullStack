using Microsoft.EntityFrameworkCore;
using portfolio.Data.GenericRepository;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;

namespace portfolio.Data
{
    public class GenericRepository<T> : IGenericRepository<T>
        where T : class
    {
        #region Constructor Declaration
        private readonly DBEntities _dbcontext;
        internal DbSet<T> DbSet;
        internal IQueryable<T> query;

        public GenericRepository(DBEntities dBContext)
        {
            _dbcontext = dBContext;
            this.DbSet = _dbcontext.Set<T>();
            this.query = _dbcontext.Set<T>();
        }
        #endregion

        #region Method Implementation

        /// <summary>
        ///Here We have to Generally follow the Func Defination with DB Context 
        /// </summary>
        /// <param name="includes"></param>
        /// <returns></returns>
        public IQueryable<T> GetAll(Expression<Func<T, object>>[]? includes = null)
        {
            try
            {
                //Here We have to Generally follow the Func Defination with DB Context 
                if(includes != null)
                {
                    IQueryable<T> query = _dbcontext.Set<T>();
                    query = includes.Aggregate<Expression<Func<T, object>>
                            , IQueryable<T>>(query, (current, expression) => current.Include(expression));

                    return query.AsQueryable();
                }
                else
                {
                    return query.AsQueryable();
                }
            }
            catch(Exception)
            {
                throw;
            }
        }


        /// <summary>
        /// Here We Generally Use the Linq with the Expression and also it has Where Condition in it
        /// </summary>
        /// <param name="where"></param>
        /// <param name="includes"></param>
        /// <returns></returns>
        public IQueryable<T> GetWhere(Expression<Func<T, bool>> where, Expression<Func<T, object>>[]? includes = null)
        {
            try
            {
                if(includes != null)
                {
                    //IQueryable<T> query = _dbcontext.Set<T>();
                    query = includes.Aggregate<Expression<Func<T, object>>
                            , IQueryable<T>>(query, (current, expression) => current.Include(expression));

                    return query.Where(where).AsQueryable();
                }
                else
                {
                    return query.Where(where).AsQueryable();
                }
            }
            catch(Exception)
            {
                throw;
            }
        }

        /// <summary>
        ///  For Getting Single Value Against a Given Condition
        /// </summary>
        /// <param name="where"></param>
        /// <param name="includes"></param>
        /// <returns></returns>
        public async Task<T> GetSingle(Expression<Func<T, bool>> where, Expression<Func<T, object>>[]? includes = null)
        {
            try
            {
                if (includes != null)
                {
                    query = includes.Aggregate<Expression<Func<T, object>>, IQueryable<T>>(query, (current, expression) => current.Include(expression));
                    return await query.Where(where).AsNoTracking().FirstOrDefaultAsync();

                }
                else
                {
                    return await query.Where(where).AsNoTracking().FirstOrDefaultAsync();
                }
            }
            catch(Exception)
            {
                throw;
            }
        }

        /// <summary>
        ///  For Getting a variable from the Particular ID
        /// </summary>
        /// <param name="id"></param>
        /// <param name="includes"></param>
        /// <returns></returns>
        public async Task<T> GetById(long id,Expression<Func<T, object>>[]? includes = null)
        {
            try
            {
                if(includes != null)
                {
                    query = includes.Aggregate<Expression<Func<T, object>>, IQueryable<T>>(query, (current, expression) => current.Include(expression));

                    return await _dbcontext.Set<T>().FindAsync(id);
                }
                else
                {
                    return await _dbcontext.Set<T>().FindAsync(id);
                }

            }
            catch (Exception)
            {
                throw;
            }
        }

        /// <summary>
        ///  For Create the Particular Repository
        /// </summary>
        /// <param name="entity"></param>
        /// <returns></returns>
        public async Task Create(T entity)
        {
            try
            {
                await _dbcontext.Set<T>().AddAsync(entity);
            }
            catch(Exception)
            {
                throw;
            }
        }

        /// <summary>
        ///  For Creating List the Particular Repository
        /// </summary>
        /// <param name="entity"></param>
        /// <returns></returns>
        public async Task CreateList(List<T> entity)
        {
            try
            {
                //await DbSet.AddRangeAsync(entity);
                await _dbcontext.Set<List<T>>().AddRangeAsync(entity);
            }
            catch(Exception)
            {
                throw;
            }

        }

        /// <summary>
        ///  For Update the Particular Repository
        /// </summary>
        /// <param name="entity"></param>
        /// <returns></returns>
        public async Task Update(T entity)
        {
            try
            {
                _dbcontext.Set<T>().Update(entity);
                //_dbcontext.Entry(entity).State = EntityState.Modified;
            }
            catch(Exception)
            {
                throw;
            }
        }

        /// <summary>
        ///  For Updating List the Particular Repository
        /// </summary>
        /// <param name="entity"></param>
        /// <returns></returns>
        public async Task UpdateList(List<T> entity)
        {
            try
            {
                _dbcontext.Set<List<T>>().Update(entity);
            }
            catch(Exception)
            {
                throw;
            }
        }

        /// <summary>
        /// For Saving the Particular Repository
        /// </summary>
        /// <returns></returns>
        public async Task Save()
        {
            try
            {
                await _dbcontext.SaveChangesAsync();
            }
            catch(Exception)
            {
                throw;
            }
        }

        private bool disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (disposing)
                {
                    _dbcontext.Dispose();
                }
                this.disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion



    }
}
