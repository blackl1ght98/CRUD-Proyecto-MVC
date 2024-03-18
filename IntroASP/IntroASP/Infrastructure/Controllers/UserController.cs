using IntroASP.Models.ViewModels;
using IntroASP.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using IntroASP.Application.Interfaces;
using IntroASP.Application.Services;
using IntroASP.Application.DTOs;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace IntroASP.Infrastructure.Controllers
{
    public class UserController : Controller
    {
        private readonly PubContext _context;
        private readonly IEmailService _emailService;
        private readonly HashService _hashService;
        private readonly IConfirmEmailService _confirmEmailService;
        private readonly IChangePassService _changePassService;

        public UserController(PubContext context, IEmailService emailService, HashService hashService, IConfirmEmailService confirmEmailService, IChangePassService changePassService)
        {
            _context = context;
            _emailService = emailService;
            _hashService = hashService;
            _confirmEmailService = confirmEmailService;
            _changePassService = changePassService;
        }

        public IActionResult Index()
        {
            var usuarios = _context.Usuarios.ToList();
            return View(usuarios);
        }
        public IActionResult Create()
        {


            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(UserViewModel model)
        {
            //Esto toma en cuenta las validaciones puestas en BeerViewModel
            if (ModelState.IsValid)
            {
                // Verificar si el email ya existe en la base de datos
                var existingUser = _context.Usuarios.FirstOrDefault(u => u.Email == model.Email);
                if (existingUser != null)
                {
                    // Si el usuario ya existe, retornar a la vista con un mensaje de error
                    ModelState.AddModelError("Email", "Este email ya está registrado.");
                    return View(model);
                }

                var resultadoHash = _hashService.Hash(model.Password);
                var user = new Usuario()
                {
                    Email = model.Email,
                    Password = resultadoHash.Hash,
                    Salt = resultadoHash.Salt,
                    Rol = "user",
                    NombreCompleto = model.NombreCompleto,
                    FechaNacimiento = model.FechaNacimiento,
                    Telefono = model.Telefono,
                    Direccion = model.Direccion,
                    FechaRegistro = DateTime.Now
                };

                _context.Add(user);
                await _context.SaveChangesAsync();
                await _emailService.SendEmailAsyncRegister(new DTOEmail
                {
                    ToEmail = model.Email
                });
                return RedirectToAction(nameof(Index));
            }
            return View(model);
        }
        [Route("UserController/ConfirmRegistration/{UserId}/{Token}")]
        public async Task<IActionResult> ConfirmRegistration(DTOConfirmRegistration confirmar)
        {

            var usuarioDB = await _context.Usuarios.FirstOrDefaultAsync(x => x.Id == confirmar.UserId);
            if (usuarioDB.ConfirmacionEmail != false)
            {
                return BadRequest("Usuario ya validado con anterioridad");
            }

            if (usuarioDB.EnlaceCambioPass != confirmar.Token)
            {
                return BadRequest("Token no valido");
            }
            await _confirmEmailService.ConfirmEmail(new DTOConfirmRegistration
            {
                UserId = confirmar.UserId
            });
            return RedirectToAction("Index", "User");
        }
    
        //Con esto mostramos al usuario la vista login
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            //ModelState.IsValid comprueba si el modelo es valido
            if (ModelState.IsValid)

            {
                //Se busca al usuario por el email
                //Se busca al usuario por el email
                var user = await _context.Usuarios.FirstOrDefaultAsync(u => u.Email == model.Email);

                if (user != null)
                {
                    //Se llama al servicio de hash para comprobar la contraseña que se ha escrito
                    var resultadoHash = _hashService.Hash(model.Password, user.Salt); // Usa la contraseña ingresada por el usuario

                    if (user.Password == resultadoHash.Hash) // Compara el hash almacenado con el hash generado
                    {
                        var claims = new List<Claim>
                        {
            new Claim(ClaimTypes.Name, user.Email),
            // puedes agregar más claims aquí si los necesitas
                        };

                        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                        var principal = new ClaimsPrincipal(identity);

                        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                        return RedirectToAction("Index", "Beer");
                    }
                    else
                    {
                        //La sintaxis de un mensaje de error personalizado es ModelState.AddModelError("","") que
                        //lo primero es la clave que lo que se refiere al campo que afecta dicho error y el segundo
                        //valor es el mensaje de error si el primer valor se pone "" esto se llama clave vacia
                        //para que una clave vacia se muestre es imprescindible poner en la vista  @Html.ValidationSummary(true, "", new { @class = "text-danger" })

                        ModelState.AddModelError("", "El email y/o la contraseña son incorrectos.");
                        //ModelState.AddModelError("Email", "El email es incorrecto.");
                        //ModelState.AddModelError("Password", "El password es incorrecto.");
                        return View(model);
                    }
                }

                return View(model);

            }

            return View(model);
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }
        public async Task<ActionResult> Edit(int id)
        {
            // Obtienes el usuario de la base de datos
            Usuario user = await _context.Usuarios.FindAsync(id);

            // Creas un nuevo ViewModel y llenas sus propiedades con los datos del usuario
            UsuarioEditViewModel viewModel = new UsuarioEditViewModel
            {
                Id = user.Id,
                Email = user.Email,
                NombreCompleto = user.NombreCompleto,
                FechaNacimiento = user.FechaNacimiento,
                Telefono = user.Telefono,
                Direccion = user.Direccion
            };

            // Pasas el ViewModel a la vista
            return View(viewModel);
        }




        //Cuando quieres editar algo de tu modelo de base de datos pero no quieres que se puedan editar determinados campos
        //lo que se realiza es una vista del modelo para especificar que campos se quieren cambiar 
        [HttpPost]
        public async Task<ActionResult> Edit(UsuarioEditViewModel userVM)
        {
            if (ModelState.IsValid)
            {
                // Obtén la entidad Usuario correspondiente de la base de datos
                var user = await _context.Usuarios.FindAsync(userVM.Id);

                if (user == null)
                {
                    return NotFound();
                }

                // Mapea los datos del ViewModel a la entidad
                user.NombreCompleto = userVM.NombreCompleto;
                //user.Email = userVM.Email;
                user.FechaNacimiento=userVM.FechaNacimiento;
                user.Telefono = userVM.Telefono;
                user.Direccion = userVM.Direccion;
             


                if (user != null && user.Email != userVM.Email)
                {

                    user.ConfirmacionEmail = false;
                    user.Email = userVM.Email;
                    _context.Usuarios.Update(user);
                    await _context.SaveChangesAsync();
                    await _emailService.SendEmailAsyncRegister(new DTOEmail
                    {
                        ToEmail = userVM.Email
                    });
                }
                else
                {
                    user.Email = userVM.Email;
                }
                if (!string.IsNullOrEmpty(userVM.Password))
                {
                    var resultadoHash = _hashService.Hash(userVM.Password, user.Salt);
                    //Si la contraseña que se intenta cambiar pones la misma que hay en base de datos
                    //se le muestra al usuario el mensaje que hay en Unauthorized
                    if (user.Password != resultadoHash.Hash)
                    {
                        await _changePassService.ChangePassId(user, userVM.Password);
                    }
                    else
                    {
                        user.Password= resultadoHash.Hash;
                    }
                }


                try
                {
                    _context.Entry(user).State = EntityState.Modified;
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!UserExists(user.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction("Index");
            }
            return View(userVM);
        }

        private bool UserExists(int Id)
        {
            Console.WriteLine("BeerId: " + Id);  // Agrega esta línea para depurar
            return _context.Usuarios.Any(e => e.Id == Id);
        }
    }
}
