using IntroASP.Models;
using Microsoft.EntityFrameworkCore;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);
string connectionString;
string secret;

//Este proyecto esta usando la plantilla MVC que quiere decir modelo vista controlador
//El agregado de la cadena de conexion no cambia la forma de hacerlo con esto me refiero que se hace igual en un proyecto web api y uno mvc
//La cadena de conexion se encuentra en el archivo de secretos de usuario
bool isDevelopment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development";
if (!isDevelopment)
{
    connectionString = builder.Configuration["CONNECTION_STRING"];
    secret = builder.Configuration["ClaveJWT"];
}
else
{
    connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
    secret = builder.Configuration["ClaveJWT"];
}
//Al igual que en un proyecto web api se pone la inyecion de dependencias
builder.Services.AddDbContext<PubContext>(options =>
{
    options.UseSqlServer(connectionString);
    options.UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking);
}
);
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(builder =>
    {
        builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
    });
});

builder.Services.AddHttpContextAccessor();

builder.Services.AddEndpointsApiExplorer();
// Add services to the container.
builder.Services.AddControllersWithViews().AddJsonOptions(options => options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles); ;
builder.Services.AddAuthentication();
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseCors();
app.UseAuthentication();
app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
