using IntroASP.Application.Services;
using IntroASP.Infrastructure.Repositories;
using IntroASP.Interfaces.Application;
using IntroASP.Interfaces.Infrastructure;
using IntroASP.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
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
builder.Services.AddTransient<HashService>();

builder.Services.AddTransient<INewStringGuid, NewStringGuid>();
builder.Services.AddTransient<IEmailService, EmailService>();
builder.Services.AddTransient<IConfirmEmailService, ConfirmEmailService>();
builder.Services.AddTransient<IChangePassService, ChangePassService>();
builder.Services.AddMvc(); 
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
builder.Services.AddSession();
builder.Services.AddControllersWithViews().AddJsonOptions(options => options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles); ;
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

    // options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
    .AddCookie(options =>
    {
        options.Cookie.HttpOnly = true;                    //la cookie solo puede ser accedida por el servidor
        options.ExpireTimeSpan = TimeSpan.FromMinutes(60);//tiempo de expiracion de la cookie
        options.LoginPath = "/User/Login";//Donde se reedirige al usuario cuando intenta acceder a algo que no tiene permisos
        options.AccessDeniedPath = "/Home/AccessDenied";
        options.SlidingExpiration = true;//mientras exista actividad en la pagina la sesion no cerrara 
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;//con esto solo se envia a traves de conexiones https
        options.Cookie.SameSite = SameSiteMode.Strict;//Esta opci�n previene el env�o de la cookie en solicitudes de sitios cruzados. Esto ayuda a prevenir ataques de falsificaci�n de solicitudes entre sitios (CSRF).
        options.Cookie.MaxAge = TimeSpan.FromMinutes(60);//Cuanto dura la sesion al usuario
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    //SI SE CAMBIA EL NOMBRE DE HOMECONTROLLER AQUI TAMBIEN ES NECESARIO QUE SE CAMBIE
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseCors();
app.UseSession();
app.UseAuthentication();
app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
