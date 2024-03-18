using IntroASP.Application.DTOs;
using IntroASP.Models;

namespace IntroASP.Application.Interfaces
{
    public interface IChangePassService
    {
        Task ChangePassId(Usuario usuarioDB, string newPass);

    }
}
