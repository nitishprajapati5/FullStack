using portfolio.Models;
using portfolio.Services;
using portfolioapi;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Hosting;



var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddTransient<RequestProcessor>();
builder.Services.AddTransient<portfolio.Data.UnitofWork.UnitOfWork>();
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddTransient<IDataServices, DataServices>();
builder.Configuration.GetSection("AppConfig").Get<AppConfig>();
builder.Services.Configure<AppConfig>(builder.Configuration.GetSection("AppConfig"));
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
//app.UseAuthorization();
app.UseMiddleware<Middleware>();
app.UseRouting();
app.MapControllers();

app.Run();

