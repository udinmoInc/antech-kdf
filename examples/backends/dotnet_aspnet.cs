// Backend Integration Example: C# + ASP.NET Core
// Demonstrates strictly where AntechKdf.Hash() and AntechKdf.Verify() are invoked.

namespace Antech.Examples
{
    public class UserService
    {
        public string RegisterUser(string password)
        {
            return AntechKdf.Hash(password);
        }

        public bool LoginUser(string password, string storedHash)
        {
            return AntechKdf.Verify(password, storedHash);
        }
    }
}
