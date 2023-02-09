using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Rendering;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace portfolio.Shared
{
    public static class CommonLib
    {
        public const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        public static IHostingEnvironment? HostingEnvironment { get; set; }

        public static long UTCSecondDifference = 0;
        public static long UTCMinuteDifference = 0;

        public static List<SelectListItem> DisabledList = new List<SelectListItem>()
        {
            new SelectListItem{Text = "Yes",Value = "Yes"},
            new SelectListItem{Text = "No",Value = "No"}
        };

        public static List<SelectListItem> OSList = new List<SelectListItem>()
        {
            new SelectListItem{Text = "Android",Value = "Android"},
            new SelectListItem{Text = "iOS",Value = "iOS"},
            new SelectListItem{Text = "Web",Value = "Web"}

        };

        /// <summary>
        /// Function to Create Directory
        /// </summary>
        /// <param name="strPath"></param>
        public static void CheckDir(string strPath)
        {
            if (!Directory.Exists(strPath))
            {
                Directory.CreateDirectory(strPath);
            }
        }

        /// <summary>
        /// Creates error message from Exception
        /// </summary>
        /// <param name="_message"></param>
        public static void WriteToFile(string _message)
        {
            var webRootInfo = HostingEnvironment.WebRootPath;
            string _Location = webRootInfo + "/ErrorLogs";

            CommonLib.CheckDir(_Location);
            _Location = System.IO.Path.Combine(_Location, DateTime.Today.ToString("dd-MM-yyyy") + ".txt");
            try
            {
                StreamWriter _sw = new StreamWriter(_Location);
                _sw.Write(_message);
                _sw.Close();
            }
            catch
            {

            }
        }

        public static void LogError(Exception ex)
        {
            string _Error = "";

            if (ex != null)
            {
                _Error = "============================" + Environment.NewLine;
                _Error = _Error + "Date        :" + DateTime.Today.ToLongDateString() + " " + DateTime.Now.ToLongTimeString() + Environment.NewLine;

                //Also Can Add Http Context
                _Error = _Error + "Error Desc :" + ex.Message + Environment.NewLine;
                _Error = _Error + "Source     :" + ex.Source + Environment.NewLine;
                _Error = _Error + "Line No    :" + ex.StackTrace + Environment.NewLine;
                _Error = _Error + "Help Link  :" + ex.HelpLink + Environment.NewLine;
                _Error = _Error + "===============================";
            }
            WriteToFile(_Error);
        }

        public static string ConvertObjectToJson(object obj, bool isFormat = false)
        {
            if (obj != null)
            {
                if (isFormat)
                {
                    return JsonConvert.SerializeObject(obj, new JsonSerializerSettings
                    {
                        ContractResolver = new Newtonsoft.Json.Serialization.CamelCasePropertyNamesContractResolver()
                    });
                }
                else
                {
                    return JsonConvert.SerializeObject(obj);
                }
            }
            return string.Empty;
        }

        public static string IsNullString(this object str)
        {
            try
            {
                return str == null ? "" : str.ToString().Trim();
            }
            catch
            {
                return string.Empty;
            }
        }

        public static DateTime? GetLocalTime(this DateTime? dt)
        {
            if (dt != null)
                return TimeZoneInfo.ConvertTimeFromUtc(dt.Value, TimeZoneInfo.Local);
            return dt;
        }

        public static T ConvertJsonToObject<T>(object obj)
        {
            return (T)JsonConvert.DeserializeObject(obj.IsNullString(), typeof(T));
        }

        public static string GetHeaderValue(IHeaderDictionary headers, string key)
        {
            if (!String.IsNullOrEmpty(headers[key]))
            {
                return headers[key];
            }
            return null;
        }

        public static string GetHeaderValue(Dictionary<string, object> headers, string key)
        {
            if (headers != null && headers.TryGetValue(key, out object value))
            {
                return Convert.ToString(value);
            }

            return null;
        }

        public static bool ContainsKeyValue<T, Y>(Dictionary<T, Y> dictionary, T expectedKey)
        {
            try
            {
                return dictionary.TryGetValue(expectedKey, out Y actualValue)
                        && !string.IsNullOrEmpty(Convert.ToString(actualValue));
            }
            catch (Exception)
            {
                throw;
            }
        }
    }

        //public static ReqHeader GetReqHeaders(IHeaderDictionary headers)
        //{
        //    ReqHeader ReqHeaders = new ReqHeader();
        //    ReqHeaders.apiVersion = CommonLib.GetHeaderValue(headers, "apiVersion");
        //    ReqHeaders.appVersion = CommonLib.GetHeaderValue(headers, "appVersion");
        //    ReqHeaders.channelId = CommonLib.GetHeaderValue(headers, "channelId");
        //    ReqHeaders.cifId = CommonLib.GetHeaderValue(headers, "cifId");
        //    ReqHeaders.deviceId = CommonLib.GetHeaderValue(headers, "deviceId");
        //    ReqHeaders.modelname = CommonLib.GetHeaderValue(headers, "modelname");
        //    ReqHeaders.languageId = CommonLib.GetHeaderValue(headers, "languageId");
        //    ReqHeaders.os = CommonLib.GetHeaderValue(headers, "os");
        //    ReqHeaders.osVersion = CommonLib.GetHeaderValue(headers, "osVersion");
        //    ReqHeaders.requestUUID = CommonLib.GetHeaderValue(headers, "requestUUID");
        //    ReqHeaders.serReqId = CommonLib.GetHeaderValue(headers, "serReqId");
        //    ReqHeaders.sessionId = CommonLib.GetHeaderValue(headers, "sessionId");
        //    ReqHeaders.sVersion = CommonLib.GetHeaderValue(headers, "sVersion");
        //    ReqHeaders.timeStamp = CommonLib.GetHeaderValue(headers, "timeStamp");
        //    return ReqHeaders;
        //}

        namespace Leap.Models
    {
        #region Limited Models

        public class ResStatus
        {
            [DefaultValue(false)]
            public bool IsSuccess { get; set; }
            public string Message { get; set; }

            //[DefaultValue("")]
            public string StatusCode { get; set; }
        }

        public class ResJsonOutput
        {
            public ResJsonOutput()
            {
                //Header = new Header();
                Data = new object();
                Status = new ResStatus();
            }
            //public Header Header { get; set; }        
            public object Data { get; set; }
            public ResStatus Status { get; set; }
        }


        public class ResJsonOutputList
        {
            public ResJsonOutputList()
            {
                Data = new List<ResJsonOutput>();
            }

            public List<ResJsonOutput> Data { get; set; }
        }

        public class ReqHeader
        {
            public string apiVersion { get; set; }
            public string appVersion { get; set; }
            public string channelId { get; set; }
            public string cifId { get; set; }
            public string deviceId { get; set; }
            public string modelname { get; set; }
            public string languageId { get; set; }
            public string os { get; set; }
            public string osVersion { get; set; }
            public string requestUUID { get; set; }
            public string serReqId { get; set; }
            public string sessionId { get; set; }
            public string sVersion { get; set; }
            public string timeStamp { get; set; }
        }

        public class KeyValue
        {
            public KeyValue() { }

            public KeyValue(string _Key, string _Value)
            {
                Key = _Key;
                Value = _Value;
            }
            public string Key { get; set; }
            public string Value { get; set; }
        }


        #endregion

    }

}

