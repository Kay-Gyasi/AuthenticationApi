using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using AuthenticationApi.Models;
using AuthenticationApi.Data;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationApi
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            services.Configure<JWT>(Configuration.GetSection("JWT"));

            //User Manager Service
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                // configure identity options
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequiredLength = 6;
                options.User.RequireUniqueEmail = true;
            }).AddEntityFrameworkStores<ApplicationDbContext>();


            //Adding DB Context with MSSQL
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"),
                    b =>
                        b.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.FullName)));



            services.AddControllers();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "AuthenticationApi", Version = "v1" });
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "AuthenticationApi v1"));
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }


        //public  IServiceCollection AddIdentityConnectionProvider(IServiceCollection services, IConfiguration configuration
        //)
        //{
        //    // var connection = GetConnectionString(configuration);

        //    //Configuration from AppSettings
        //    services.Configure<JWT>(configuration.GetSection("JWT"));
        //    //User Manager Service
        //    services.AddIdentity<ApplicationUser, IdentityRole>(options =>
        //        {
        //            // configure identity options
        //            options.Password.RequireDigit = false;
        //            options.Password.RequireLowercase = false;
        //            options.Password.RequireUppercase = false;
        //            options.Password.RequireNonAlphanumeric = false;
        //            options.Password.RequiredLength = 6;
        //            options.User.RequireUniqueEmail = true;
        //        })
        //        .AddEntityFrameworkStores<ApplicationDbContext>();


        //    //Adding DB Context with MSSQL
        //    services.AddDbContext<ApplicationDbContext>(options =>
        //        options.UseSqlServer(connection,
        //            b =>
        //                b.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.FullName)));

        //    return services;
        //}
    }
}
