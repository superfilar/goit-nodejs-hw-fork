const fs = require("fs/promises");
const { nanoid } = "nanoid";
const dataFile = "models/contacts.json";

const listContacts = async () => {
  try {
    const data = await fs.readFile(dataFile, "utf8");
    return JSON.parse(data);
  } catch (error) {
    console.error("Error reading contacts data:", error);
    return [];
  }
};

const getContactById = async (contactId) => {
  try {
    const data = await fs.readFile(dataFile, "utf8");
    const contacts = JSON.parse(data);
    return contacts.find((contact) => contact.id === contactId);
  } catch (error) {
    console.error("Error finding contact by ID:", error);
    return null;
  }
};

const removeContact = async (contactId) => {
  try {
    const data = await fs.readFile(dataFile, "utf8");
    let contacts = JSON.parse(data);
    contacts = contacts.filter((contact) => contact.id !== contactId);
    await fs.writeFile(dataFile, JSON.stringify(contacts, null, 2));
    return contacts;
  } catch (error) {
    console.error("Error removing contact:", error);
    return [];
  }
};

const addContact = async (body) => {
  try {
    const data = await listContacts();
    const newContact = { id: String(Date.now()), ...body };
    data.push(newContact);
    await fs.writeFile(dataFile, JSON.stringify(data, null, 2));
    return newContact;
  } catch (error) {
    console.error("Error adding new contact:", error);
    return null;
  }
};

const updateContact = async (contactId, body) => {
  try {
    const data = await listContacts();
    const index = data.findIndex((contact) => contact.id === contactId);
    if (index === -1) return null;
    const updatedContact = { ...data[index], ...body };
    data[index] = updatedContact;
    await fs.writeFile(dataFile, JSON.stringify(data, null, 2));
    return updatedContact;
  } catch (error) {
    console.error("Error updating contact:", error);
    return null;
  }
};

module.exports = {
  listContacts,
  getContactById,
  removeContact,
  addContact,
  updateContact,
};
