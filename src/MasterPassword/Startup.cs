using MasterPassword.BusinessLogic;
using MasterPassword.BusinessLogic.RequestHandlers;
using MasterPassword.DataAccess.MongoDbAtlas;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi;
using System;

namespace MasterPassword
{
    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment webHostEnvironment)
        {
            _configuration = configuration;
            _webHostEnvironment = webHostEnvironment;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDistributedMemoryCache();
            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(60);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
            });

            services.AddAuthentication("Custom")
                .AddScheme<MasterPasswordAuthOptions, MasterPasswordAuthenticationHandler>("Custom", null);

            //services.AddApiVersioning(options =>
            //{
            //    options.DefaultApiVersion = new ApiVersion(AppVersion.Major, AppVersion.Minor);
            //    options.AssumeDefaultVersionWhenUnspecified = true;
            //    options.ApiVersionReader = ApiVersionReader.Combine(new HeaderApiVersionReader("x-api-version"),
            //        new MediaTypeApiVersionReader("x-api-version"),
            //        new QueryStringApiVersionReader());
            //});

            services.AddHealthChecks();
            services.AddControllersWithViews();

            services.AddBusinessLogic()
                    .AddDataAccess(GetConnectionString("MongoDbAtlas"));

            if (_webHostEnvironment.IsDevelopment())
            {
                services.AddSwaggerGen(t => {
                    t.SwaggerDoc("v1", new OpenApiInfo() { Title = "Master Password API", Version = "v1" });
                    });
            }
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(t => { t.SwaggerEndpoint("/swagger/v1/swagger.json", $"Master Password API - {_webHostEnvironment.EnvironmentName}"); });
            }

            app.UseStaticFiles()
                .UseRouting()
                .UseSession();

            app.UseAuthentication()
                .UseAuthorization()
                .UseHealthChecks("/health");

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                     name: "default",
                     pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        private string GetConnectionString(string name)
        {
            if (_webHostEnvironment.IsProduction())
                return Environment.GetEnvironmentVariable($"CUSTOMCONNSTR_{name}");

            return _configuration.GetConnectionString(name);
        }

        private IConfiguration _configuration;
        private IWebHostEnvironment _webHostEnvironment;
    }
}
