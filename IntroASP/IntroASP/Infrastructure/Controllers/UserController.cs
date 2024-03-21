using IntroASP.Models.ViewModels;
using IntroASP.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using IntroASP.Application.Services;
using IntroASP.Application.DTOs;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Authorization;
using System.Text;
using IntroASP.Interfaces.Application;

namespace IntroASP.Infrastructure.Controllers
{
    public class UserController : Controller
    {
        private readonly PubContext _context;
        private readonly IEmailService _emailService;
        private readonly HashService _hashService;
        private readonly IConfirmEmailService _confirmEmailService;
        private readonly IChangePassService _changePassService;
        private readonly IHttpContextAccessor _contextAccessor;

        public UserController(PubContext context, IEmailService emailService, HashService hashService, IConfirmEmailService confirmEmailService, IChangePassService changePassService, IHttpContextAccessor contextAccessor)
        {
            _context = context;
            _emailService = emailService;
            _hashService = hashService;
            _confirmEmailService = confirmEmailService;
            _changePassService = changePassService;
            _contextAccessor = contextAccessor;
        }
        //Vista principal del controlador donde alvergara las funciones de este controlador
        //Aqui hemos usado la vista principal para traer todos los datos del usuario

        public IActionResult Index()
        {
            //Obtiene los datos de los roles, recordemos que selectList se le pasan varios  elementos 
            //primero la funente de informacion
            //segundo el identificador
            //tercero lo que ve el usuario
            ViewData["Roles"] = new SelectList(_context.Roles, "Id", "Nombre");
            var usuarios = _context.Usuarios.Include(x=>x.IdRolNavigation).ToList();
            return View(usuarios);
        }
        //Como en la vista principal se han obtenido todos los datos de procede a actualizar el rol
        //UpdateRole no tiene ninguna vista independiente porque ya se llama en la vista principal

        [Authorize(Roles = "administrador")]
        [HttpPost]
        public IActionResult UpdateRole(int id, int newRole)
        {
            var user = _context.Usuarios.Find(id);
            if (user == null)
            {
                return NotFound();
            }
            //crea el desplegable
            ViewData["Roles"] = new SelectList(_context.Roles, "Id", "Nombre");

            user.IdRol = newRole;
            _context.Usuarios.Update(user);
            _context.SaveChanges();
            return RedirectToAction(nameof(Index));
        }
        //Creacion de un usuario. Esto reedirige a una vista que contiene lo que ve el admin cuando crea un usuario
        [Authorize(Roles = "administrador")]
        public IActionResult Create()
        {
            //Sirve para obtener los datos del desplegable
            ViewData["Roles"] = new SelectList(_context.Roles, "Id", "Nombre");

            return View();
        }
      

        [HttpPost]
        //Sirve para que no se altere la informacion del formulario
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
                    IdRol=model.IdRol,
                    //Rol = "user",
                    NombreCompleto = model.NombreCompleto,
                    FechaNacimiento = model.FechaNacimiento,
                    Telefono = model.Telefono,
                    Direccion = model.Direccion,
                    FechaRegistro = DateTime.Now
                };
                //Sirve para crear el desplegable
                ViewData["Roles"] = new SelectList(_context.Roles, "Id", "Nombre");

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
        //Con esto se consigue manejar datos de la ruta, este endpoint se llama en el email service cuando se le manda el correo electronico
        //al usuario y el usuario hace clic en el enlace este metodo es llamado
        [AllowAnonymous]
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
        [AllowAnonymous]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _context.Usuarios.Include(x => x.IdRolNavigation).FirstOrDefaultAsync(u => u.Email == model.Email);

                if (user != null)
                {
                    // Comprobar si el correo electrónico ha sido confirmado
                    if (!user.ConfirmacionEmail)
                    {
                        ModelState.AddModelError("", "Por favor, confirma tu correo electrónico antes de iniciar sesión.");
                        return View(model);
                    }

                    var resultadoHash = _hashService.Hash(model.Password, user.Salt);

                    if (user.Password == resultadoHash.Hash)
                    {
                        var claims = new List<Claim>
                        {
                            new Claim(ClaimTypes.Name, user.Email),
                            new Claim(ClaimTypes.Role, user.IdRolNavigation.Nombre),
                            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),//Maneja que usuario esta logueado actualmente
                        };

                        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                        var principal = new ClaimsPrincipal(identity);

                        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                        return RedirectToAction("Index", "Beer");
                    }
                    else
                    {
                        ModelState.AddModelError("", "El email y/o la contraseña son incorrectos.");
                        return View(model);
                    }
                }

                return View(model);
            }

            return View(model);
        }
        [AllowAnonymous]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }
        //Con esto se muestra la vista para editar el usuario
        [Authorize(Roles = "administrador")]
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
        //lo que se realiza es una vista del modelo para especificar que campos se quieren cambiar (UsuarioEditViewModel)


        [HttpPost]
        public async Task<ActionResult> Edit(UsuarioEditViewModel userVM)
        {
            //Si el modelo es valido:
            if (ModelState.IsValid)
            {
                // Obtiene la id del usuario a editar
                var user = await _context.Usuarios.FindAsync(userVM.Id);

                if (user == null)
                {
                    return NotFound("Usuario no encontrado");
                }

                // Mapea los datos del ViewModel a la entidad
                user.NombreCompleto = userVM.NombreCompleto;
                user.FechaNacimiento=userVM.FechaNacimiento;
                user.Telefono = userVM.Telefono;
                user.Direccion = userVM.Direccion;
             

                //Esto ocurre cuando el usuario cambia de email 
                if (user != null && user.Email != userVM.Email)
                {
                    //La confirmacion de email se le cambia a false
                    user.ConfirmacionEmail = false;
                    //El nuevo email se asigna a base de datos
                    user.Email = userVM.Email;
                    _context.Usuarios.Update(user);
                    await _context.SaveChangesAsync();
                    //Se envia un emain para confirmar el nuevo correo
                    await _emailService.SendEmailAsyncRegister(new DTOEmail
                    {
                        ToEmail = userVM.Email
                    });
                }
                else
                {
                    //Si el usuario no cambia el email se queda igual
                    user.Email = userVM.Email;
                }
             


                try
                {
                    //Marca la entidad Usuarios como modificada
                    /*El método Entry en el contexto de Entity Framework Core se utiliza para obtener un objeto 
                     * que puede usarse para configurar y realizar acciones en una entidad que está siendo rastreada por el contexto.*/
                    /*

    Update(user): Este método marca la entidad y todas sus propiedades como modificadas. Esto significa que cuando llamas a SaveChangesAsync(), 
                    Entity Framework generará un comando SQL UPDATE que actualizará todas las columnas de la entidad en la base de datos, 
                    independientemente de si cambiaron o no.

    Entry(user).State = EntityState.Modified: Este método marca la entidad como modificada, pero no todas las propiedades. Cuando llamas a 
                    SaveChangesAsync(), Entity Framework generará un comando SQL UPDATE que sólo actualizará las columnas de la entidad que 
                    realmente cambiaron.
*/
                    _context.Entry(user).State = EntityState.Modified;
                    await _context.SaveChangesAsync();
                }
                //esta excepcion es lanzada cuando varios usuarios modifican al mismo tiempo los datos. Por ejemplo
                //tenemos un usuario llamado A que esta modificando los datos y todavia no ha guardado esos cambios pero
                //tenemos un usuario B que tiene que modificar los datos que esta modificando el usuario A y el usuario B 
                //guarda los datos antes que el A por lo tanto al usuario A tener datos antiguos se produce esta excepcion al usuario
                //A no tener los datos actuales
                catch (DbUpdateConcurrencyException)
                {
                    if (!UserExists(user.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        // Recarga los datos del usuario desde la base de datos
                        _context.Entry(user).Reload();

                        // Intenta guardar de nuevo
                        _context.Entry(user).State = EntityState.Modified;
                        await _context.SaveChangesAsync();
                    }
                }
                return RedirectToAction("Index");
            }
            return View(userVM);
        }

        private bool UserExists(int Id)
        {
          
            return _context.Usuarios.Any(e => e.Id == Id);
        }



        //Vista que se muestra al eliminar el usuario
        [Authorize(Roles = "administrador")]
        public async Task<IActionResult> Delete(int id)
        {
        
            //Consulta a base de datos en base a la id del usuario
            var user = await _context.Usuarios.FirstOrDefaultAsync(m => m.Id == id);
            //Si no hay cervezas muestra el error 404
            if (user == null)
            {
                return NotFound("Usuario no encontrado");
            }
            //Llegados ha este punto hay cervezas por lo tanto se muestran las cervezas
            return View(user);
        }


        [HttpPost, ActionName("DeleteConfirmed")]
        [ValidateAntiForgeryToken]
        //Para que detecte la id del usuario es necesario poner el mismo nombre que se ponga en la vista en la
        //parte del asp-for del formulario tenemos Id por lo tanto aqui tambien hay que ponerlo
        //El asp-for si tu ahi le pasar Id lo que va a ir a buscar es algo que sea Id si se pone en minuscula no lo encuentra
        public async Task<IActionResult> DeleteConfirmed(int Id)
        {
            var user = await _context.Usuarios.FirstOrDefaultAsync(m => m.Id == Id);
            if (user == null)
            {
                return BadRequest();
            }
            _context.Usuarios.Remove(user);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }
        //Este metodo toma el email por ruta y ademas envia un email al usuario con lo que tiene que hacer para resetear la contraseña
     

        [Route("UserController/ResetPassword/{email}")]
        [Authorize(Roles = "administrador")]
        //Esto le muestra una vista al administrador
        public async Task<IActionResult> ResetPassword(string email)
        {
            var usuarioDB = await _context.Usuarios.AsTracking().FirstOrDefaultAsync(x => x.Email == email);
            // Generar una contraseña temporal
            await _emailService.SendEmailAsyncResetPassword(new DTOEmail
            {
                ToEmail = email
            });
            return View(usuarioDB);
        }
        //De ese email que se ha enviado del enlace tomamos el id de usuario y el token que no es token lo que genera es un
        //identificador unico, este identificador se genero cuando el usuario se registro, con esto nos asguramos de que la contraseña
        //se cambia para el usuario correcto
        [AllowAnonymous]
        [Route("UserController/RestorePassword/{UserId}/{Token}")]
        public async Task<IActionResult> RestorePassword(DTORestorePass cambio)
        {
            var usuarioDB = await _context.Usuarios.FirstOrDefaultAsync(x => x.Id == cambio.UserId);
            if (usuarioDB.Email == null)
            {
                return BadRequest("Email no encontrado");
            }

            if (usuarioDB.EnlaceCambioPass != cambio.Token)
            {
                return BadRequest("Token no valido");
            }

            // Crear un nuevo objeto DTORestorePass y establecer las propiedades apropiadas
            var restorePass = new DTORestorePass
            {
                UserId = usuarioDB.Id,
                Token = usuarioDB.EnlaceCambioPass,
                // Puedes establecer otras propiedades aquí si es necesario
            };

            // Pasar el objeto DTORestorePass a la vista
            return View(restorePass);
        }
        //En la vista para restaurar la contraseña llamamos a este metodo para que la contraseña sea restaurada
        //esto es la logica que hay detras del formulario para restaurar la contraseña
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> RestorePasswordUser(DTORestorePass cambio)
        {
            var usuarioDB = await _context.Usuarios.FirstOrDefaultAsync(x => x.Id == cambio.UserId);
            if (usuarioDB == null)
            {
                return BadRequest("Usuario no encontrado");
            }
            // Comprobar si la contraseña es nula
            if (string.IsNullOrEmpty(cambio.Password))
            {
                return BadRequest("La contraseña no puede estar vacía");
            }
            // Comprobar si la contraseña temporal es válida
            var resultadoHashTemp = _hashService.Hash(cambio.TemporaryPassword);
            usuarioDB.TemporaryPassword = resultadoHashTemp.Hash;
            usuarioDB.Salt = resultadoHashTemp.Salt;
            if (usuarioDB.TemporaryPassword != resultadoHashTemp.Hash || usuarioDB.Salt != resultadoHashTemp.Salt)
            {
                return BadRequest("La contraseña temporal no es válida");
            }
            _context.Usuarios.Update(usuarioDB);
            await _context.SaveChangesAsync();
            var resultadoHash = _hashService.Hash(cambio.Password);
            // Actualizar la contraseña del usuario
            usuarioDB.Password = resultadoHash.Hash;
            usuarioDB.Salt = resultadoHash.Salt;

            // Guardar los cambios en la base de datos
            _context.Usuarios.Update(usuarioDB);
            await _context.SaveChangesAsync();

            return RedirectToAction("Index", "User");
        }




    }
}
