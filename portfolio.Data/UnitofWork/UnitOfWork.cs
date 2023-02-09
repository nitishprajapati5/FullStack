using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace portfolio.Data.UnitofWork
{
    public class UnitOfWork : IDisposable
    {

        #region Private Member Declaration
        private DBEntities _context = null;
        private IConfiguration _configuration;
        #endregion

        #region Constructor Region
        public UnitOfWork(IConfiguration configuration)
        {
            this._configuration = configuration;
            var options = new DbContextOptionsBuilder<DBEntities>();

            //Connection String
            string connectionstring = "";

            options.UseSqlServer(connectionstring);
        }
        #endregion

        #region Public Method Declaration

        public async Task Save()
        {
            try
            {
                await _context.SaveChangesAsync();
            }
            catch (Exception)
            {
                throw;
            }

        }
        #region IDisposable Implementation

        private bool disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (disposing)
                {
                    //_context.Dispose();
                }
            }
            this.disposed = true;
        }

        /// <summary>
        /// Dispose Method
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion


        private Dictionary<string, object> repositories;

        public GenericRepository<T> Repository<T>() where T : class
        {
            if (repositories == null)
            {
                repositories = new Dictionary<string, object>();
            }

            var type = typeof(T).Name;
            if (repositories.ContainsKey(type)) return (GenericRepository<T>)repositories[type];

            var repositoryType = typeof(GenericRepository<>);
            var repositoryInstance = Activator.CreateInstance(repositoryType
                                                               .MakeGenericType(typeof(T)),
                                                               _context);

            repositories.Add(type, repositoryInstance);
            return (GenericRepository<T>)repositories[type];


        }

        /// <summary>
        /// Return First Row of Object Rest of The Rows are ignored
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="SpName"></param>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public async Task<T> ExecuteScalarAsync<T>(string SpName, List<SqlParameter> parameters = null)
        {
            T obj = default(T);
            var conn = _context.Database.GetDbConnection();

            try
            {
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = SpName;
                    cmd.Connection = conn;
                    cmd.CommandType = CommandType.StoredProcedure;
                    if (parameters != null)
                    {
                        cmd.Parameters.AddRange(parameters.ToArray());
                    }

                    if (conn.State != ConnectionState.Open)
                    {
                        conn.Close();
                        conn.Open();
                    }

                    var t = await cmd.ExecuteScalarAsync();
                    if (t != DBNull.Value)
                    {
                        obj = (T)t;
                    }
                    conn.Close();
                }
            }

            catch (Exception)
            {
                throw;
            }
            finally
            {
                conn.Close();
            }
            return obj;
        }

        /// <summary>
        /// Returns Class Result
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="SpName"></param>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public T ExecuteScalar<T>(string SpName, List<SqlParameter> parameters = null)
        {
            T obj = default(T);
            var conn = _context.Database.GetDbConnection();
            try
            {
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = SpName;
                    cmd.Connection = conn;
                    cmd.CommandType = CommandType.StoredProcedure;

                    if (parameters != null)
                    {
                        cmd.Parameters.Add(parameters.ToArray());
                    }

                    if (conn.State != ConnectionState.Open)
                    {
                        conn.Close();
                        conn.Open();
                    }

                    var t = cmd.ExecuteScalar();
                    if (t != DBNull.Value)
                    {
                        obj = (T)t;
                    }
                    conn.Close();

                }
            }
            catch (Exception)
            {
                throw;
            }
            finally
            {
                conn.Close();
            }

            return obj;
        }


        /// <summary>
        /// Returns True or False according to the .NET Execution
        /// </summary>
        /// <param name="SpName"></param>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public async Task<int> ExcuteNonQueryAsync(string SpName, List<SqlParameter> parameters = null)
        {
            int i = 0;
            var conn = _context.Database.GetDbConnection();
            try
            {
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = SpName;
                    cmd.Connection = conn;
                    cmd.CommandType = CommandType.StoredProcedure;
                    //Generally Used for Adding Parameters
                    if (parameters != null)
                    {
                        cmd.Parameters.Add(parameters.ToArray());
                    }
                    //Checking the State of Connection 

                    if (conn.State != ConnectionState.Open)
                    {
                        conn.Close();
                        conn.Open();
                    }
                    i = await cmd.ExecuteNonQueryAsync();
                    conn.Close();
                }
            }
            catch (Exception)
            {
                throw;
            }
            finally
            {
                conn.Close();
            }
            return i;
        }


        /// <summary>
        /// List of Tables in the Object
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="SpName"></param>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public async Task<List<T>> ExecuteSP<T>(String SpName, List<SqlParameter> parameters = null)
        {
            List<T> result = new List<T>();
            var conn = _context.Database.GetDbConnection();
            try
            {
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = SpName;
                    cmd.Connection = conn;
                    cmd.CommandType = CommandType.StoredProcedure;
                    if (parameters != null)
                    {
                        cmd.Parameters.Add(parameters.ToArray());
                    }
                    if (conn.State != ConnectionState.Open)
                    {
                        conn.Close();
                        conn.Open();
                    }

                    using (var reader = await cmd.ExecuteReaderAsync())
                    {
                        var mapper = new DataReaderMapper<T>();
                        result = mapper.MapListAll(reader);
                    }

                    conn.Close();
                }

            }
            catch (Exception) { throw; }
            finally { conn.Close(); }

            return result;
        }

        //public async Task<List<T>> ExecuteSpOptimizedwithJson(string SpName,List<SqlParameter> parameters = null)
        //{
        //    List<T> result = new List<T>();

        //}
        /// <summary>
        /// Gets Mutiple DataSet Result with JSON Output
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="SpName"></param>
        /// <param name="parameters"></param>
        /// <returns></returns>

        public T GetMultipleResult<T>(string SpName,List<SqlParameter> parameters = null)
        {
            try
            {
                var conn = _context.Database.GetDbConnection();
                using(SqlConnection con = new SqlConnection())
                {
                    using(SqlCommand cmd = new SqlCommand(SpName))
                    {
                        cmd.Connection = new SqlConnection(conn.ConnectionString);
                        cmd.CommandType = CommandType.StoredProcedure;
                        if(parameters != null)
                        {
                            cmd.Parameters.AddRange(parameters.ToArray());
                        }
                        if(conn.State != ConnectionState.Open)
                        {
                            conn.Close();
                            conn.Open();
                        }
                        using(SqlDataAdapter sda = new SqlDataAdapter(cmd))
                        {
                            DataSet ds = new DataSet();
                            sda.Fill(ds);

                            if(ds.Tables.Count > 0)
                            {
                                //return CommonLib.ConvertJsonToObject<T>(CommonLib.ConvertObjectToJson(ds));
                            }
                        }
                    }
                    con.Close();
                }

                return default(T);
            }
            catch(Exception ex) 
            {
                //CommonLib.LogError(ex);
                throw; 
            }

        }
            #endregion

        #region Mapper Region
            public class DataReaderMapper<T>
            {
                
                public List<T> MapListAll(IDataReader reader)
                {
                    return MapListExcludeColumns(reader);
                }

                public List<T> MapListExcludeColumns(IDataReader reader,params string[] excludeColumns)
                {
                    var listOfObjects = new List<T>();
                    while (reader.Read())
                    {
                        listOfObjects.Add(MapRowExclude(reader, excludeColumns));
                    }
                    return listOfObjects; 

                }

                public T MapRowExclude(IDataReader reader, params string[] columns)
                {
                     return MapRow(reader, false, columns);
                }

                public T MapRowInclude(IDataReader reader, params string[] columns)
                {
                    return MapRow(reader, true, columns);
                }

                public T MapRowAll(IDataReader reader)
                {
                     return MapRow(reader, true, null);
                }

                private T MapRow(IDataReader reader, bool includeColumns, params string[] columns)
                {
                    T item = Activator.CreateInstance<T>();// 1. 
                    var properties = GetPropertiesToMap(includeColumns, columns); // 2. 
                    foreach (var property in properties)
                    {
                        try
                        {
                            int ordinal = reader.GetOrdinal(property.Name); // 3. 
                            if (!reader.IsDBNull(ordinal)) // 4.
                            {
                                // if dbnull the property will get default value, 
                                // otherwise try to read the value from reader
                                property.SetValue(item, reader[ordinal], null); // 5.
                            }
                        }
                        catch { }
                    }
                    return item;
                }

            public IEnumerable<System.Reflection.PropertyInfo> GetPropertiesToMap(bool includeColumns, string[] columns)
                {

                    var properties = typeof(T).GetProperties().Where(y =>
                                     (y.PropertyType.Equals(typeof(string)) ||
                                      y.PropertyType.Equals(typeof(byte[])) ||
                                      y.PropertyType.IsValueType) &&
                                      (columns == null || (columns.Contains(y.Name) == includeColumns)));
                    
                    return properties;
                }

        
           
            }
        #endregion
    }
}
