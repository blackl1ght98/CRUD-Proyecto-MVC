using IntroASP.Application.DTOs;
using IntroASP.Application.Interfaces;
using IntroASP.Infrastructure.Interfaces;
using MailKit.Security;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewEngines;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Mvc;
using MimeKit.Text;
using MimeKit;
using IntroASP.Models;
using Microsoft.EntityFrameworkCore;
using MailKit.Net.Smtp;
using System.Text;

namespace IntroASP.Application.Services
{
    public class EmailService:IEmailService
    {
        private readonly IConfiguration _config;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly INewStringGuid _newStringGuid;
        private readonly PubContext _context;
        private readonly IServiceProvider _serviceProvider;
        private readonly ICompositeViewEngine _viewEngine;
        private readonly ITempDataProvider _tempDataProvider;
        private readonly HashService _hashService;


        public EmailService(IConfiguration config, IHttpContextAccessor httpContextAccessor,
            INewStringGuid newStringGuid, PubContext context, ITempDataProvider tempDataProvider,
            ICompositeViewEngine viewEngine, IServiceProvider serviceProvider, HashService hashService)
        {
            _config = config;
            _httpContextAccessor = httpContextAccessor;
            _newStringGuid = newStringGuid;
            _context = context;
            _tempDataProvider = tempDataProvider;
            _viewEngine = viewEngine;
            _serviceProvider = serviceProvider;
            _hashService = hashService;
        }


        public async Task SendEmailAsyncRegister(DTOEmail userDataRegister)
        {

            var usuarioDB = await _context.Usuarios.AsTracking().FirstOrDefaultAsync(x => x.Email == userDataRegister.ToEmail);

            Guid miGuid = Guid.NewGuid();
            string textoEnlace = Convert.ToBase64String(miGuid.ToByteArray());
            textoEnlace = textoEnlace.Replace("=", "").Replace("+", "").Replace("/", "").Replace("?", "").Replace("&", "").Replace("!", "").Replace("¡", "");
            usuarioDB.EnlaceCambioPass = textoEnlace;
           // var enlace = $"http://localhost:4200/login/";

            var model = new DTOEmail
            {
                //RecoveryLink = $"http://localhost:4200/login/{usuarioDB.EnlaceCambioPass}",
                //RecoveryLink = $"http://localhost:4200/login/confirm-email/{usuarioDB.Id}/{usuarioDB.EnlaceCambioPass}",
                //RecoveryLink = $"http://localhost:4200/shared/redireccion/{usuarioDB.Id}/{usuarioDB.EnlaceCambioPass}",
                RecoveryLink = $"{_httpContextAccessor.HttpContext.Request.Scheme}://{_httpContextAccessor.HttpContext.Request.Host}/UserController/ConfirmRegistration/{usuarioDB.Id}/{usuarioDB.EnlaceCambioPass}?redirect=true",
            };

            await _newStringGuid.SaveNewStringGuid(usuarioDB);

            var ruta = await RenderViewToStringAsync("ViewRegisterEmail", model);

            var email = new MimeMessage();
            email.From.Add(MailboxAddress.Parse(_config.GetSection("Email:UserName").Value));
            email.To.Add(MailboxAddress.Parse(userDataRegister.ToEmail));
            email.Subject = "Confirmar Email";
            email.Body = new TextPart(TextFormat.Html)
            {
                Text = await RenderViewToStringAsync("ViewRegisterEmail", model)
            };

            using var smtp = new SmtpClient();
            await smtp.ConnectAsync(
                _config.GetSection("Email:Host").Value,
                Convert.ToInt32(_config.GetSection("Email:Port").Value),
                SecureSocketOptions.StartTls
            );

            await smtp.AuthenticateAsync(_config.GetSection("Email:UserName").Value, _config.GetSection("Email:PassWord").Value);
            await smtp.SendAsync(email);
            await smtp.DisconnectAsync(true);
        }

        public async Task SendEmailAsyncChangePassword(DTOEmail userData)
        {

            var usuarioDB = await _context.Usuarios.AsTracking().FirstOrDefaultAsync(x => x.Email == userData.ToEmail);

            DateTime fecha = DateTime.Now.AddHours(+1);
            Guid miGuid = Guid.NewGuid();
            string textoEnlace = Convert.ToBase64String(miGuid.ToByteArray());
            textoEnlace = textoEnlace.Replace("=", "").Replace("+", "").Replace("/", "").Replace("?", "").Replace("&", "").Replace("!", "").Replace("¡", "");
            usuarioDB.EnlaceCambioPass = textoEnlace;
            usuarioDB.FechaEnlaceCambioPass = fecha;
           

            var model = new DTOEmail
            {
                //RecoveryLink = $"http://localhost:4200/recover-pass/{usuarioDB.EnlaceCambioPass}",

                //RecoveryLink = $"http://localhost:4200/shared/recover-pass/{textoEnlace}",
                //RecoveryLink = $"{_httpContextAccessor.HttpContext.Request.Scheme}://{_httpContextAccessor.HttpContext.Request.Host}/shared/recover-pass/{textoEnlace}?redirect=true",
                RecoveryLink = $"{_httpContextAccessor.HttpContext.Request.Scheme}://{_httpContextAccessor.HttpContext.Request.Host}/UserController/ConfirmRegistration/{textoEnlace}?redirect=true"
            };

            await _newStringGuid.SaveNewStringGuid(usuarioDB);

            var ruta = await RenderViewToStringAsync("RecoverPassword", model);

            var email = new MimeMessage();
            email.From.Add(MailboxAddress.Parse(_config.GetSection("Email:UserName").Value));
            email.To.Add(MailboxAddress.Parse(userData.ToEmail));
            email.Subject = "Recuperar contraseña";
            email.Body = new TextPart(TextFormat.Html)
            {
                Text = await RenderViewToStringAsync("RecoverPassword", model)
            };

            using var smtp = new SmtpClient();
            await smtp.ConnectAsync(
                _config.GetSection("Email:Host").Value,
                Convert.ToInt32(_config.GetSection("Email:Port").Value),
                SecureSocketOptions.StartTls
            );

            await smtp.AuthenticateAsync(_config.GetSection("Email:UserName").Value, _config.GetSection("Email:PassWord").Value);
            await smtp.SendAsync(email);
            await smtp.DisconnectAsync(true);

        }
        //---------------------------------------------------------------------------------------------------
        public async Task SendTempPassword(DTOEmail userData)
        {

            var usuarioDB = await _context.Usuarios.AsTracking().FirstOrDefaultAsync(x => x.Email == userData.ToEmail);

            DateTime fecha = DateTime.Now.AddHours(+1);
            Guid miGuid = Guid.NewGuid();
            string textoEnlace = Convert.ToBase64String(miGuid.ToByteArray());
            textoEnlace = textoEnlace.Replace("=", "").Replace("+", "").Replace("/", "").Replace("?", "").Replace("&", "").Replace("!", "").Replace("¡", "");
            usuarioDB.EnlaceCambioPass = textoEnlace;
            usuarioDB.FechaEnlaceCambioPass = fecha;
         

            var model = new DTOEmail
            {
                //RecoveryLink = $"http://localhost:4200/recover-pass/{usuarioDB.EnlaceCambioPass}",

                //RecoveryLink = $"http://localhost:4200/shared/recover-pass/{textoEnlace}",
                //RecoveryLink = $"{_httpContextAccessor.HttpContext.Request.Scheme}://{_httpContextAccessor.HttpContext.Request.Host}/shared/recover-pass/{textoEnlace}?redirect=true",
                RecoveryLink = $"{_httpContextAccessor.HttpContext.Request.Scheme}://{_httpContextAccessor.HttpContext.Request.Host}/UserController/ResetPassword/{usuarioDB.Id}/{usuarioDB.EnlaceCambioPass}?redirect=true"
            };

            await _newStringGuid.SaveNewStringGuid(usuarioDB);

            var ruta = await RenderViewToStringAsync("RecoverPassword", model);

            var email = new MimeMessage();
            email.From.Add(MailboxAddress.Parse(_config.GetSection("Email:UserName").Value));
            email.To.Add(MailboxAddress.Parse(userData.ToEmail));
            email.Subject = "Recuperar contraseña";
            email.Body = new TextPart(TextFormat.Html)
            {
                Text = await RenderViewToStringAsync("RecoverPassword", model)
            };

            using var smtp = new SmtpClient();
            await smtp.ConnectAsync(
                _config.GetSection("Email:Host").Value,
                Convert.ToInt32(_config.GetSection("Email:Port").Value),
                SecureSocketOptions.StartTls
            );

            await smtp.AuthenticateAsync(_config.GetSection("Email:UserName").Value, _config.GetSection("Email:PassWord").Value);
            await smtp.SendAsync(email);
            await smtp.DisconnectAsync(true);

        }





        private async Task<string> RenderViewToStringAsync(string viewName, object model)
        {
            var httpContext = new DefaultHttpContext { RequestServices = _serviceProvider };
            var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());

            using (var sw = new StringWriter())
            {
                var viewResult = _viewEngine.FindView(actionContext, viewName, false);

                if (viewResult.View == null)
                {
                    throw new ArgumentNullException($"{viewName} does not match any available view");
                }

                var viewDictionary = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
                {
                    Model = model
                };

                var viewContext = new ViewContext(
                    actionContext,
                    viewResult.View,
                    viewDictionary,
                    new TempDataDictionary(actionContext.HttpContext, _tempDataProvider),
                    sw,
                    new HtmlHelperOptions()
                );

                await viewResult.View.RenderAsync(viewContext);

                return sw.ToString();
            }


        }
    }
}
