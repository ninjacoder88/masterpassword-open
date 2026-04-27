using MasterPassword.DataAccess.MongoDbAtlas;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MasterPassword.BusinessLogic.LoadNotes
{
    public interface ILoadNotesRequestHandler
    {
        Task<LoadNotesResponse> HandleAsync(LoadNotesRequest request);
    }

    internal sealed class LoadNotesRequestHandler(IMongoDbRepository Repository, IEncryptor Encryptor) : ILoadNotesRequestHandler
    {
        public async Task<LoadNotesResponse> HandleAsync(LoadNotesRequest request)
        {
            if (request == null)
                return new LoadNotesResponse(false) { ErrorMessage = "No data was received in the request" };

            if (string.IsNullOrEmpty(request.PrimaryAccountId))
                return new LoadNotesResponse(false) { ErrorMessage = "Invalid pid" };

            if (string.IsNullOrEmpty(request.SecondaryAccountId))
                return new LoadNotesResponse(false) { ErrorMessage = "Invalid sid" };

            var primaryAccountById = await Repository.LoadPrimaryAccountByIdAsync(request.PrimaryAccountId);
            byte[] encryptionKeyBytes = Encoding.UTF8.GetBytes(request.UserKey);

            //var secondaryAccountIds =
            //    primaryAccountById.SecondaryAccounts.Select(x => x.SecondaryAccountId)
            //                                        .Select(x => Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, x))
            //                                        .ToList();

            //if (!secondaryAccountIds.Contains(request.SecondaryAccountId))
            //    return new LoadNotesResponse(false) { ErrorMessage = "This is not your account. Stop it" };

            var secondaryAccountById = await Repository.LoadSecondaryAccountByIdAsync(request.SecondaryAccountId);
            if(secondaryAccountById.PrimaryAccountId != primaryAccountById._id.ToString())
                return new LoadNotesResponse(false) { ErrorMessage = "This is not your account. Stop it" };

            //var noteIds = secondaryAccountById.NoteIds.Select(x => Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, x)).ToList();

            var notes = await Repository.LoadNotesForSecondaryAccountAsync(secondaryAccountById._id.ToString());

            var decryptedNotes = notes.Select(x => new
            {
                Id = x._id.ToString(),
                Title = Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, x.Title),
                Description = Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, x.Description)
            });

            return new LoadNotesResponse(true) { Notes = decryptedNotes };
        }
    }
}
