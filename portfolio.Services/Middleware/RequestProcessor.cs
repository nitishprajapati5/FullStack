using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using portfolio.Models;
using portfolio.Shared;
using portfolio.Shared.Leap.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace portfolio.Services
{
    public class RequestProcessor
    {

        private readonly HttpContext _context;
        //private readonly AppConfig _appConfig;

        private readonly string modelName = "Middleware";
        private DateTime requestDateTime;

        private FormattedRequest formattedRequest = null;
        private FormattedResponse formattedResponse = null;

        public RequestProcessor(IHttpContextAccessor httpContextAccessor)
        {
            _context = httpContextAccessor.HttpContext;
        }

        public async Task ProcessRequest(RequestDelegate _next)
        {
            try
            {
                requestDateTime = DateTime.Now;
                //get formatted Request

                #region Request Region

                if (_context != null && _context.Response != null && _context.Request.Method == HttpMethod.Post.Method)
                {
                    _context.Request.Body = await PrepareMBRequest();
                }

                #endregion


                #region Response Region

                var existingBody = _context.Response.Body;

                using(var newBody = new MemoryStream())
                {
                    _context.Response.Body = newBody;

                    await _next.Invoke(_context);

                    _context.Response.Body = new MemoryStream();

                    newBody.Seek(0, SeekOrigin.Begin);
                    _context.Response.Body = existingBody;

                    using(var newContent = new StreamReader(newBody))
                    {
                        var json = await PrepareMBResponse(newContent);

                        await _context.Response.WriteAsync(json);
                    }

                }


                #endregion

            }
            catch (Exception ex) 
            {

            }

        }

        /// <summary>
        /// Prepare MB Request
        /// </summary>
        /// <returns></returns>
        private async Task<Stream> PrepareMBRequest()
        {
            try
            {
                object request = formattedRequest.GatewayRequest.Request;

                if (request != null && ((request.GetType() == typeof(System.String) && !string.IsNullOrEmpty(Convert.ToString(request))) ||
                                        (request.GetType() == typeof(JObject) && ((Newtonsoft.Json.Linq.JContainer)request).HasValues)))
                {
                    //Decrypt request and pass plain text object to MB API
                    /*if (isEncryption && !isIntegration)
                    {
                        formattedRequest.GatewayRequest.Header.TryGetValue(ProgConstants.DeviceID, out object deviceId);
                        formattedRequest.GatewayRequest.Header.TryGetValue(ProgConstants.RequestUUID, out object requestUUID);
                        formattedRequest.GatewayRequest.Header.TryGetValue(ProgConstants.SVersion, out object sVersion);

                        //get password
                        string password = AESEncryptDecrypt.CreatePassword(string.Format("{0}{1}", requestUUID, deviceId), Convert.ToInt32(sVersion));

                        //Decrypt
                        request = AESEncryptDecrypt.Decrypt(request, password);
                    }
                    */
                    //var a = CommonLib.ConvertJsonToObject<object>(request);
                    var json = request.GetType().IsSerializable ? Convert.ToString(request) : CommonLib.ConvertObjectToJson(request);

                    //replace request stream to downstream handlers
                    var requestContent = new StringContent(json, Encoding.UTF8, "application/json");

                    //_MiddlewareLogs(await requestContent.ReadAsStringAsync());
                    //modified stream
                    return await requestContent.ReadAsStreamAsync();
                }
                //else
                //{
                //    _MiddlewareLogs("PrepareMBRequest Failure"); //store _MiddlewareLogs
                //}

                return _context.Request.Body;
            }
            catch(Exception ex)
            {
                throw;
            }
        }

        private async Task<String> PrepareMBResponse(StreamReader content)
        {
            try
            {
                using (content)
                {
                    var response = JsonConvert.DeserializeObject<ResJsonOutput>(await content.ReadToEndAsync());

                    formattedResponse = new FormattedResponse();
                    ///formattedResponse.GatewayResponse.Header = formattedRequest.GatewayRequest.Header;
                    //formattedResponse.GatewayResponse.Status = response.Status;
                    formattedResponse.GatewayResponse.Response = new ResData { Data = response.Data };//isDependent ? response.Data : new ResData { Data = response.Data };

                    /*                    if (response.Status.IsSuccess && isEncryption && !isIntegration)
                    {
                        formattedRequest.GatewayRequest.Header.TryGetValue(ProgConstants.DeviceID, out object deviceId);
                        formattedRequest.GatewayRequest.Header.TryGetValue(ProgConstants.RequestUUID, out object requestUUID);

                        //get index
                        int index = AESEncryptDecrypt.GenerateIndex();

                        //get password
                        string password = AESEncryptDecrypt.CreatePassword(string.Format("{0}{1}", requestUUID, deviceId), index);

                        //assign encrypted response
                        formattedResponse.GatewayResponse.Response = AESEncryptDecrypt.Encrypt(CommonLib.ConvertObjectToJson(formattedResponse.GatewayResponse.Response, true), password);

                        //Update header value for sVersion
                        if (formattedRequest.GatewayRequest.Header.Keys.Contains(ProgConstants.SVersion))
                        {
                            //formattedRequest.GatewayRequest.Header[ProgConstants.SVersion] = index;
                            Dictionary<string, object> Header = new Dictionary<string, object>(formattedRequest.GatewayRequest.Header)
                            {
                                [ProgConstants.SVersion] = index,
                            };

                            formattedResponse.GatewayResponse.Header = Header;
                        }
                    }

                     */

                    return CommonLib.ConvertObjectToJson(formattedResponse, true);

                }
            }
            catch(Exception)
            {
                throw;
            }

        }
    }
}
