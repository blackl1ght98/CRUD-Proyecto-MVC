using IntroASP.Application.DTOs;

namespace IntroASP.Application.Interfaces
{
    public interface IConfirmEmailService
    {
        Task ConfirmEmail(DTOConfirmRegistration confirm);

    }
}
