using MasterPassword.DataAccess.MongoDbAtlas;
using MasterPassword.DataAccess.MongoDbAtlas.Entities;
using System.Text;
using System.Threading.Tasks;

namespace MasterPassword.BusinessLogic.CreateNote
{
    public interface ICreateNoteRequestHandler
    {
        Task<CreateNoteResponse> HandleAsync(CreateNoteRequest request);
    }

    internal sealed class CreateNoteRequestHandler(IMongoDbRepository Repository, IEncryptor Encryptor) : ICreateNoteRequestHandler
    {
        public async Task<CreateNoteResponse> HandleAsync(CreateNoteRequest request)
        {
            //todo: add more validation relating to the secondary account belonging to the primary account
            if (request is null)
                return new CreateNoteResponse(false) { ErrorMessage = "No data received with this request" };

            if (string.IsNullOrWhiteSpace(request.UserKey))
                return new CreateNoteResponse(false) { ErrorMessage = "Invalid key" };

            var secondaryAccount = await Repository.LoadSecondaryAccountByIdAsync(request.SecondaryAccountId);

            if (secondaryAccount is null)
                return new CreateNoteResponse(false) { ErrorMessage = "Could not find secondary account" };

            byte[] encryptionKeyBytes = Encoding.UTF8.GetBytes(request.UserKey);

            var encryptedTitle = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, request.Title);
            var encryptedDescription = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, request.Description);

            var note = new Note { Title = encryptedTitle, Description = encryptedDescription, SecondaryAccountId = secondaryAccount._id.ToString() };

            var noteId = await Repository.CreateNoteAsync(note);

            var encryptedNoteId = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, noteId);
            //await Repository.UpdateSecondaryAccountNoteIdsAsync(request.SecondaryAccountId, encryptedNoteId);

            return new CreateNoteResponse(true) { NoteId = noteId };
        }
    }
}
