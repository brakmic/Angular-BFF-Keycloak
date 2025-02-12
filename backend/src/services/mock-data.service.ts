/**
 * mock-data.service.ts
 * 
 * Description:
 *  - Generates fake user data, transactions, and product data using Faker.
 *  - Helps simulate "backend" responses for testing and development.
 * 
 * API:
 *  - Classes & Interfaces:
 *      MockDataService:
 *        - getUserDetails(): Returns a single "UserDetails" object with random values.
 *        - getTransactions(count): Returns an array of "Transaction" objects.
 *        - getProducts(count): Returns an array of "Product" objects.
 *        - getProfileExtensions(): Returns additional profile fields for extended data.
 *      UserDetails: Interface describing user address, phone, etc.
 *      Transaction: Interface describing financial transaction info.
 *      Product: Interface describing product info (name, price, etc.).
 * 
 * @module services/mock-data.service
 */
import { faker } from '@faker-js/faker';

export interface UserDetails {
  address: {
    street: string;
    city: string;
    zipCode: string;
    country: string;
  };
  phone: string;
  company: string;
  recentLogin: string;
}

export interface Transaction {
  id: string;
  date: string;
  amount: string;
  currency: string;
  merchant: string;
  type: string;
}

export interface Product {
  id: string;
  name: string;
  price: string;
  department: string;
  material: string;
  description: string;
  inStock: boolean;
}

export class MockDataService {
  static getUserDetails(): UserDetails {
    return {
      address: {
        street: faker.location.streetAddress(),
        city: faker.location.city(),
        zipCode: faker.location.zipCode(),
        country: faker.location.country()
      },
      phone: faker.phone.number(),
      company: faker.company.name(),
      recentLogin: faker.date.recent().toISOString()
    };
  }

  static getTransactions(count: number = 5): Transaction[] {
    return Array.from({ length: count }, () => ({
      id: faker.string.uuid(),
      date: faker.date.past().toISOString(),
      amount: faker.finance.amount({ min: 10, max: 1000, dec: 2 }),
      currency: faker.finance.currencyCode(),
      merchant: faker.company.name(),
      type: faker.helpers.arrayElement(['debit', 'credit'])
    }));
  }

  static getProducts(count: number = 8): Product[] {
    return Array.from({ length: count }, () => ({
      id: faker.commerce.isbn(),
      name: faker.commerce.productName(),
      price: faker.commerce.price({ min: 10, max: 500 }),
      department: faker.commerce.department(),
      material: faker.commerce.productMaterial(),
      description: faker.commerce.productDescription(),
      inStock: faker.datatype.boolean()
    }));
  }

  static getProfileExtensions() {
    return {
      fakeBio: faker.person.bio(),
      registeredAt: faker.date.past({ years: 2 }).toISOString(),
      avatar: faker.image.avatar(),
      socialMedia: {
        twitter: faker.internet.userName(),
        github: faker.internet.userName()
      }
    };
  }
}