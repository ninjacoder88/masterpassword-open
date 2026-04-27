using HtmlAgilityPack;
using MasterPassword.DataAccess.MongoDbAtlas;
using MasterPassword.DataAccess.MongoDbAtlas.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace MasterPassword.BusinessLogic.RequestHandlers.UpdateFavicon
{
    public interface IUpdateFaviconRequestHandler
    {
        Task<UpdateFaviconResponse> HandleAsync(UpdateFaviconRequest request);
    }

    internal sealed class UpdateFaviconRequestHandler(IMongoDbRepository Repository) : IUpdateFaviconRequestHandler
    {
        public async Task<UpdateFaviconResponse> HandleAsync(UpdateFaviconRequest request)
        {
            List<Favicon> favicons = await Repository.LoadFaviconsAsync();
            DateTimeOffset now = DateTimeOffset.Now;
            foreach(Favicon favicon in favicons)
            {
                if(!string.IsNullOrWhiteSpace(favicon.Url))
                {
                    TimeSpan diff = now - favicon.UpdateTime;
                    if(diff.TotalDays < 90)
                        continue;

                    byte[] faviconData = await GetFaviconAsync(favicon.Url);
                    if(faviconData.Length == 0)
                        favicon.Url = null;
                    else
                    {
                        favicon.Data = faviconData;
                        favicon.UpdateTime = now;
                    }
                        
                    continue;
                }

                if (string.IsNullOrEmpty(favicon.Host))
                    continue;

                byte[] faviconBytes = await GetFaviconAsync($"https://{favicon.Host}/favicon.ico");
                if (faviconBytes.Length > 0)
                {
                    favicon.Url = $"https://{favicon.Host}/favicon.ico";
                    favicon.UpdateTime = now;
                    favicon.Data = faviconBytes;
                    await Repository.UpdateFaviconAsync(favicon._id, favicon);
                    continue;
                }

                try
                {
                    string? faviconUrl = await GetIconPathFromPageAsync(favicon.Host);
                    if (string.IsNullOrWhiteSpace(faviconUrl))
                        continue;
                    byte[] faviconBytes1 = await GetFaviconAsync(faviconUrl);
                    if (faviconBytes1.Length > 0)
                    {
                        favicon.Url = faviconUrl;
                        favicon.UpdateTime = now;
                        favicon.Data = faviconBytes1;
                        await Repository.UpdateFaviconAsync(favicon._id, favicon);
                        continue;
                    }
                }
                catch(Exception ex)
                {
                    ex.GetType();
                }
            }

            return new UpdateFaviconResponse(true);
        }

        private async Task<string?> GetIconPathFromPageAsync(string host)
        {
            Tuple<bool, string> htmlResult = await GetHtmlAsync(host);
            if (htmlResult.Item1 == false)
            {
                string[] splitHost = host.Split(".");
                if (splitHost.Length < 3)
                    return null;

                host = $"{splitHost[splitHost.Length - 2]}.{splitHost[splitHost.Length - 1]}";
                htmlResult = await GetHtmlAsync(host);
                if (htmlResult.Item1 == false)
                    return null;
            }

            HtmlDocument doc = new();
            doc.LoadHtml(htmlResult.Item2);

            List<string> hrefs = new();
            foreach (var linkNode in doc.DocumentNode.SelectNodes("html/head/link"))
            {
                HtmlAttributeCollection attributes = linkNode.Attributes;
                HtmlAttribute? relAttribute = attributes.SingleOrDefault(x => x.Name == "rel");
                HtmlAttribute? hrefAttribute = attributes.SingleOrDefault(x => x.Name == "href");

                if (relAttribute is null)
                    continue;

                if (hrefAttribute is null)
                    continue;

                if (relAttribute.Value == "icon" || relAttribute.Value == "shortcut icon")
                {
                    if (hrefAttribute.Value.StartsWith("http"))
                        hrefs.Add(hrefAttribute.Value);
                    else
                        hrefs.Add($"https://{host}{hrefAttribute.Value}");
                }
            }

            return hrefs.FirstOrDefault();
        }

        private async Task<Tuple<bool, string>> GetHtmlAsync(string host)
        {
            using (HttpClient client = new HttpClient())
            {
                client.BaseAddress = new Uri($"https://{host}");
                client.DefaultRequestHeaders.Add("User-Agent", "LINQPad 8");
                HttpResponseMessage response = await client.GetAsync("");
                string content = await response.Content.ReadAsStringAsync();
                if (!response.IsSuccessStatusCode)
                {
                    return new Tuple<bool, string>(false, string.Empty);
                }
                return new Tuple<bool, string>(true, content);
            }
        }

        private async Task<byte[]> GetFaviconAsync(string url)
        {
            try
            {
                using (HttpClient client = new HttpClient())
                {
                    client.Timeout = TimeSpan.FromSeconds(3);
                    return await client.GetByteArrayAsync(url);
                }
            }
            catch (Exception ex)
            {
                //eat it
                return Array.Empty<byte>();
            }
        }
    }

    public sealed class UpdateFaviconRequest
    {

    }

    public sealed class UpdateFaviconResponse : AppResponse
    {
        public UpdateFaviconResponse(bool success) 
            : base(success)
        {
        }
    }
}
