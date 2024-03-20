using IntroASP.Application.DTOs;

namespace IntroASP.Application.Interfaces
{
    public interface IEmailService
    {
        Task SendEmailAsyncRegister(DTOEmail userData);
        Task SendEmailAsyncResetPassword(DTOEmail userDataResetPassword);
    }
}
