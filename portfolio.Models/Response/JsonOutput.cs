using Newtonsoft.Json;
using portfolio.Shared.Leap.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace portfolio.Models
{
    public class JsonOutput : ResStatus
    {
        public object Result { get; set; }
    }

    public class Header
    {
        [DisplayName("API Version")]
        public string ApiVersion { get; set; }

        [DisplayName("App Version")]
        public string AppVersion { get; set; }

        [DisplayName("Channel")]
        public string ChannelId { get; set; }

        [DisplayName("CIF")]
        public string CIFId { get; set; }

        [DisplayName("DeviceId")]
        public string DeviceId { get; set; }

        [DisplayName("Language")]
        public string LanguageId { get; set; }

        [DisplayName("Operating System")]
        public string OS { get; set; }

        [DisplayName("OS Version")]
        public string OSVersion { get; set; }
    }

    public class FormattedRequest
    {
        public FormattedRequest()
        {
            GatewayRequest = new GatewayRequest();
        }
        [JsonProperty("gatewayRequest")]
        public GatewayRequest GatewayRequest { get; set; }
    }

    public class FormattedResponse
    {
        public FormattedResponse()
        {
            GatewayResponse = new GatewayResponse();
        }
        public GatewayResponse GatewayResponse { get; set; }
    }

    public class GatewayRequest
    {
        //public GatewayRequest()
        //{

        //Header = new Dictionary<string, object>();
        //Request = new object();
        //}

        [JsonProperty("header")]
        public Dictionary<string, object> Header { get; set; }

        [JsonProperty("request")]
        public object Request { get; set; }
    }

    public class GatewayResponse
    {
        public GatewayResponse()
        {
            //Header = new Dictionary<string, object>();
            Response = new ResData();
            //Status = new ResStatus();
        }

        [JsonProperty("header")]
        public Dictionary<string, object> Header { get; set; }
        public object Response { get; set; }
        public ResStatus Status { get; set; }
    }

    public class ResData
    {
        //public ResData()
        //{
        //    Data = new object();
        //}

        public object Data { get; set; }
    }

}
